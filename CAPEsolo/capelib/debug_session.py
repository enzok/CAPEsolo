import logging
import re
from threading import Condition, Lock
from typing import Any, Dict, List, Optional, Tuple

from distorm3 import Decode, Decode32Bits, Decode64Bits

from CAPEsolo.classes.debug_pipe import CommandPipeHandler
from CAPEsolo.lib.core.pipe import PipeDispatcher, PipeServer, disconnect_pipes

log = logging.getLogger(__name__)

DEBUG_PIPE = r"\\.\pipe\debugger_pipe"
DEFAULT_COMMAND_TIMEOUT = 30
DEFAULT_BREAK_TIMEOUT = 120
MAX_TIMEOUT = 3600
MAX_MEM_READ = 0x4000
MAX_INSTRUCTIONS = 256
MAX_INSTRUCTION_LEN = 15
FAILURE_TOKENS = ("Failed", "TIMEOUT", "UNREADABLE", "NODATA")
CIP_RX = re.compile(r"\b([ER]IP):\s*([0-9A-Fa-f]+)")
ADDRESS_RX = re.compile(r"0x[0-9a-fA-F]+")
GENERAL_REG_RX = re.compile(r"\b([A-Z0-9]{2,3}):\s*([0-9A-Fa-f]{8,16})")
XMM_REG_RX = re.compile(r"\bXMM(\d{1,2})\s*\.(Low|High)\s*:\s*([0-9A-Fa-f]{8,16})")


def ParseAddress(value: Any) -> Optional[int]:
    """Accept an int or a hex string (with or without 0x) and return an address."""
    if isinstance(value, bool):
        return None

    if isinstance(value, int):
        return value if value >= 0 else None

    if not isinstance(value, str):
        return None

    text = value.strip()
    if not text:
        return None

    try:
        addr = int(text, 16)
    except ValueError:
        return None

    return addr if addr >= 0 else None


def IsFailure(payload: Optional[str]) -> bool:
    """Return whether a debug server payload reports a failure rather than data."""
    if payload is None:
        return True

    return payload.startswith(FAILURE_TOKENS)


def ParseCip(payload: str) -> Optional[int]:
    """Extract the current instruction pointer from a register dump or break payload."""
    m = CIP_RX.search(payload)
    if m:
        return int(m.group(2), 16)

    m = ADDRESS_RX.search(payload)
    if m:
        return int(m.group(0), 16)

    return None


def ParseRegisters(regsText: str) -> Dict[str, str]:
    """Parse the register display text into a name to hex value mapping."""
    registers = {}
    for name, value in GENERAL_REG_RX.findall(regsText):
        registers[name.upper()] = f"{int(value, 16):#x}"

    for num, part, value in XMM_REG_RX.findall(regsText):
        key = f"XMM{int(num):02}.{part}".upper()
        registers[key] = f"{int(value, 16):#x}"

    return registers


def ParseStack(payload: str) -> List[Dict[str, str]]:
    """Parse 'address, value' stack lines."""
    entries = []
    for line in payload.splitlines():
        parts = [p.strip() for p in line.split(",", 1)]
        if len(parts) < 2:
            continue

        entries.append({"address": parts[0], "value": parts[1]})

    return entries


def ParseMemDump(payload: str) -> Tuple[Optional[int], str]:
    """Split a memory dump payload into its request address and hex data."""
    if "|" not in payload:
        return None, ""

    requestAddr, data = payload.split("|", 1)
    try:
        return int(requestAddr, 16), data.strip()
    except ValueError:
        return None, ""


def ParseThreads(payload: str) -> List[Dict[str, Any]]:
    """Parse thread lines of the form 'marker|tid|start address'."""
    threads = []
    for line in payload.splitlines():
        parts = [p.strip() for p in line.split("|")]
        if len(parts) != 3:
            continue

        threads.append({"tid": parts[1], "start_address": parts[2], "current": parts[0] == "+"})

    threads.sort(key=lambda t: not t["current"])
    return threads


def ParseBreakpoints(payload: str) -> List[Dict[str, str]]:
    """Parse breakpoint entries of the form 'dr,address' joined by '|'."""
    if "No" in payload:
        return []

    breakpoints = []
    for bp in payload.split("|"):
        parts = bp.split(",")
        if len(parts) != 2:
            continue

        breakpoints.append({"dr": parts[0].strip(), "address": parts[1].strip()})

    return breakpoints


def ParseModules(payload: str) -> List[Dict[str, str]]:
    """Parse module entries of the form 'base,size,name,path' joined by '|'."""
    modules = []
    for mod in payload.split("|"):
        parts = mod.split(",")
        if len(parts) != 4:
            continue

        modules.append({"base": parts[0], "size": parts[1], "name": parts[2], "path": parts[3]})

    return modules


def Disassemble(base: int, data: bytes, bits: int, count: int) -> List[Dict[str, str]]:
    """Decode instructions from raw bytes read at `base`."""
    mode = Decode64Bits if bits == 64 else Decode32Bits
    instructions = []
    for address, _, text, hexBytes in Decode(base, data, mode):
        if len(instructions) >= count:
            break

        instructions.append({"address": f"{address:#x}", "bytes": hexBytes.upper(), "text": text})

    return instructions


class DebuggerSession:
    """Headless driver for the capemon interactive debugger.

    Hosts the same named pipe server as DebugConsole (classes/debug_console.py) but
    drives the CommandPipeHandler rendezvous directly instead of through a client
    handle, because an MCP tool call may block where the wx main thread may not.
    """

    def __init__(self):
        self.breakCondition = Condition()
        self.pendingCommand = None
        self.debuggerResponse = None
        self.commandPipe = None
        self.sendLock = Lock()
        self.connected = False
        self.cip = None
        self.bits = None

    def launch(self):
        """Starts the pipe server and waits for a connection from the debug server."""
        # noinspection PyTypeChecker
        self.commandPipe = PipeServer(
            PipeDispatcher,
            DEBUG_PIPE,
            message=True,
            dispatcher=CommandPipeHandler(self),
        )
        self.commandPipe.daemon = True
        self.commandPipe.start()
        log.info("[DEBUG SESSION] Debugger pipe server started.")

    def shutdown(self):
        """Stops the pipe server and disconnects any open pipes."""
        if self.commandPipe:
            try:
                self.commandPipe.stop()
            except Exception:
                log.exception("[DEBUG SESSION] Failed stopping debugger pipe server")

            self.commandPipe = None

        self.connected = False
        disconnect_pipes()

    def _TakeResponse(self) -> str:
        response = self.debuggerResponse
        self.debuggerResponse = None
        self.connected = True
        return response.decode("utf-8", errors="replace").strip()

    def UpdateCip(self, payload: str) -> Optional[int]:
        """Record the instruction pointer reported by an execution or register payload."""
        cip = ParseCip(payload)
        if cip is not None:
            self.cip = cip

        return self.cip

    def WaitForBreak(self, timeout: float = DEFAULT_BREAK_TIMEOUT) -> Optional[str]:
        """Wait for an unsolicited break notification and return its payload."""
        with self.breakCondition:
            notified = self.breakCondition.wait_for(lambda: self.debuggerResponse is not None, timeout=timeout)
            if not notified:
                return None

            payload = self._TakeResponse()
            self.UpdateCip(payload)
            return payload

    def SendCommand(self, command: str, data: str = "", timeout: float = DEFAULT_COMMAND_TIMEOUT) -> Optional[str]:
        """Send a debugger command and return its payload, or None on timeout.

        Only valid while the target is halted at a break, which is when the debug
        server is waiting for the next command.
        """
        with self.sendLock, self.breakCondition:
            if self.debuggerResponse is not None:
                stale = self._TakeResponse()
                self.UpdateCip(stale)
                log.debug("[DEBUG SESSION] Discarding unconsumed break payload: %s", stale[:64])

            self.pendingCommand = f"{command}:{data}".encode("utf-8")
            self.breakCondition.notify_all()
            notified = self.breakCondition.wait_for(lambda: self.debuggerResponse is not None, timeout=timeout)
            if not notified:
                self.pendingCommand = None
                log.warning("[DEBUG SESSION] Command %s timed out after %ss", command, timeout)
                return None

            return self._TakeResponse()
