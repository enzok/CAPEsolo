import logging
import re
import threading
from collections import namedtuple
from typing import List, Tuple

import pywintypes
import win32event
import win32file
import wx
from capstone import CS_ARCH_X86, CS_MODE_32, CS_MODE_64, Cs

from CAPEsolo.lib.core.pipe import PipeDispatcher, PipeServer, disconnect_pipes

log = logging.getLogger(__name__)

TIMEOUT = 600
BUFFER_SIZE = 0x10000
DBGCMD = "DBGCMD"

DecodedInstruction = namedtuple("DecodedInstruction", ["address", "bytes", "text"])


class DisassemblyListCtrl(wx.ListCtrl):
    def __init__(self, parent, bits=64):
        style = wx.LC_REPORT | wx.LC_VIRTUAL | wx.LC_HRULES | wx.LC_VRULES
        super().__init__(parent, style=style)
        self.parent = parent
        self.InsertColumn(0, "Address", width=120)
        self.InsertColumn(1, "Bytes", width=180)
        self.InsertColumn(2, "Disassembly", width=300)
        self.SetItemCount(0)
        self.pageMap: List[Tuple[int, int, int]] = []
        self.memCache = {}
        self.decodeCache: List[DecodedInstruction] = []
        self.pendingPageBase: int = None
        self.currentRip: int = None
        self.bits = bits
        mode = CS_MODE_64 if bits == 64 else CS_MODE_32
        self.cs = Cs(CS_ARCH_X86, mode)
        self.cs.detail = False
        self.Bind(wx.EVT_LIST_CACHE_HINT, self.OnCacheHint)
        self.Bind(wx.EVT_LIST_ITEM_ACTIVATED, self.OnItemActivated)

    def RequestPageMap(self):
        self.parent.SendCommand("P")

    def RequestPage(self, baseAddress: int):
        self.pendingPageBase = baseAddress
        self.parent.SendCommand("I", hex(baseAddress))

    def JumpTo(self, address: int):
        self.currentRip = address
        self.RequestDecodeSync(address)

    def LoadPageMap(self, data: str):
        if not data:
            return

        self.decodeCache.clear()
        self.memCache.clear()
        self.SetItemCount(0)
        entries = data.split("|")
        if not entries or entries[0] == "":
            return

        self.pageMap = []
        for entry in entries:
            try:
                base_str, size_str, protect_str = entry.split(',')
                baseAddr = int(base_str, 16)
                regionSize = int(size_str)
                protect = int(protect_str, 16)
                self.pageMap.append((baseAddr, regionSize, protect))
            except (ValueError, AttributeError) as e:
                log.error("[DEBUG CONSOLE] Failed to parse entry '%s': %s", entry, e)
                continue

        self.pageMap.sort(key=lambda x: x[0])

    def LoadPage(self, data: bytes):
        if self.pendingPageBase is None:
            return

        if isinstance(data, str):
            data = data.encode('latin-1')

        self.memCache[self.pendingPageBase] = data

    def OnCacheHint(self, evt):
        for idx in (evt.GetCacheFrom(), evt.GetCacheTo()):
            if idx < len(self.decodeCache):
                self.EnsureDecoded(self.decodeCache[idx].address)

    def EnsureDecoded(self, addr: int):
        pageBase = self.FindPage(addr)
        if pageBase not in self.memCache:
            self.RequestPage(pageBase)

    def DecodePending(self):
        base = self.pendingPageBase
        mem = self.memCache.get(base)
        if not mem:
            return

        for inst in self.cs.disasm(mem, base):
            addr = inst.address
            bts = inst.bytes
            txt = f"{inst.mnemonic} {inst.op_str}".strip()
            self.decodeCache.append(DecodedInstruction(addr, bts, txt))

        self.decodeCache.sort(key=lambda inst: inst.address)
        self.SetItemCount(len(self.decodeCache))

    def FindPage(self, addr: int) -> int:
        for base, size, _ in self.pageMap:
            if base <= addr < base + size:
                return base
        raise ValueError(f"[DEBUG CONSOLE] Address {addr:#x} not in any page")

    def OnGetItemText(self, item: int, col: int) -> str:
        if item < 0 or item >= len(self.decodeCache):
            return ""

        inst = self.decodeCache[item]
        if col == 0:
            return f"{inst.address:#010x}"

        if col == 1:
            return inst.bytes.hex()

        return inst.text

    def OnGetItemAttr(self, item: int) -> wx.ItemAttr:
        attr = wx.ItemAttr()
        if item < 0 or item >= len(self.decodeCache):
            return attr

        inst = self.decodeCache[item]
        mnem = inst.text.split()[0].lower()
        attr = wx.ItemAttr()
        if mnem == "call":
            attr.SetTextColour(wx.BLUE)
        elif mnem in ("jmp", "je", "jne", "jg", "jl"):
            attr.SetTextColour(wx.GREEN)
        return attr

    def OnItemActivated(self, evt):
        idx = evt.GetIndex()
        inst = self.decodeCache[idx]
        mnem = inst.text.split()[0].lower()
        if mnem == "call" or mnem.startswith("j"):
            rel = int(inst.text.split()[-1], 16)
            target = inst.address + len(inst.bytes) + rel
            self.JumpTo(target)

    def HighlightIp(self):
        if self.currentRip is None:
            return
        idx = self.FindInstructionIndex(self.currentRip)
        if idx != -1:
            self.Select(idx)
            self.EnsureVisible(idx)

    def RequestDecodeSync(self, address: int):
        if not self.pageMap:
            self.RequestPageMap()
            return

        pageBase = self.FindPage(address)
        if pageBase not in self.memCache:
            self.RequestPage(pageBase)
            return

        self.DecodePending()
        self.HighlightIp()

    def FindInstructionIndex(self, address: int) -> int:
        lo, hi = 0, len(self.decodeCache) - 1
        while lo <= hi:
            mid = (lo + hi) // 2
            addr = self.decodeCache[mid].address
            if addr == address:
                return mid
            if addr < address:
                lo = mid + 1
            else:
                hi = mid - 1
        return -1


class RegsTextCtrl(wx.TextCtrl):
    def __init__(self, parent, style):
        """TextCtrl subclass"""
        super().__init__(parent, style=style)
        self.parent = parent
        self.Bind(wx.EVT_CONTEXT_MENU, self.OnContextMenu)

    def OnContextMenu(self, event):
        menu = wx.Menu()
        miFollow = menu.Append(wx.ID_ANY, "Follow Value")
        menu.Bind(wx.EVT_MENU, self.OnFollowValue, miFollow)
        pos = event.GetPosition()
        pos = self.ScreenToClient(pos)
        self.PopupMenu(menu, pos)
        menu.Destroy()

    def OnFollowValue(self, event):
        sel = self.GetStringSelection().strip()
        if sel:
            self.parent.memAddressInput.SetValue(sel)
            evt = wx.CommandEvent(wx.EVT_TEXT_ENTER.typeId, self.parent.memAddressInput.GetId())
            self.parent.OnAddressEnter(evt)


class StackListCtrl(wx.ListCtrl):
    def __init__(self, parent):
        super().__init__(parent, style=wx.LC_REPORT | wx.LC_SINGLE_SEL)
        self.parent = parent
        self.spVal = None
        self.InsertColumn(0, "Address", width=170)
        self.InsertColumn(1, "Value", width=170)
        self.InsertColumn(2, "", width=170)
        self.data = []
        self.Bind(wx.EVT_CONTEXT_MENU, self.OnContextMenu)

    def UpdateData(self, data):
        """Populate the list with rows and highlight the specified index."""
        rows = []
        for line in data.splitlines():
            parts = [p.strip() for p in line.split(",", 1)]

            if len(parts) < 2:
                continue

            addr, val = parts[0], parts[1]
            rows.append((addr, val))

        regsText = self.parent.regsDisplay.GetValue()
        m = re.search(r"\b([ER]SP):\s*([0-9A-Fa-f]+)", regsText)
        self.spVal = m.group(2) if m else None
        spIdx = len(rows) // 2
        if self.spVal:
            for i, (addr, _) in enumerate(rows):
                if addr.lower() == self.spVal.lower():
                    spIdx = i
                    break

        self.DeleteAllItems()
        self.data = rows

        for i, (addr, val) in enumerate(rows):
            self.InsertItem(i, str(addr))
            self.SetItem(i, 1, str(val))
            # asciiVals = self.GetAscii(val)
            self.SetItem(i, 2, "")

            if i == spIdx:
                self.SetItemBackgroundColour(i, wx.Colour(255, 255, 150))

        self.Refresh()
        self.CenterRow(spIdx)

    @staticmethod
    def GetAscii(dataBytes) -> str:
        """Inspect an 8-byte qword for printable ASCII; return '.' for non-printable."""
        buf = dataBytes[:8].ljust(8, b"\x00")
        asciiStr = "".join(chr(b) if 32 <= b < 127 else "." for b in buf)
        return asciiStr

    def OnContextMenu(self, event):
        pos = event.GetPosition()
        pos = self.ScreenToClient(pos)
        idx, flags = self.HitTest(pos)
        if idx == wx.NOT_FOUND:
            return

        menu = wx.Menu()
        miFollowAddr = menu.Append(wx.ID_ANY, "Follow Address")
        miFollowVal = menu.Append(wx.ID_ANY, "Follow Value")

        menu.Bind(
            wx.EVT_MENU,
            lambda e, r=idx: (
                self.parent.memAddressInput.SetValue(self.data[r][0]),
                self.parent.OnAddressEnter(wx.CommandEvent(wx.EVT_TEXT_ENTER.typeId, self.parent.memAddressInput.GetId())),
            ),
            miFollowAddr,
        )
        menu.Bind(
            wx.EVT_MENU,
            lambda e, r=idx: (
                self.parent.memAddressInput.SetValue(self.data[r][1]),
                self.parent.OnAddressEnter(wx.CommandEvent(wx.EVT_TEXT_ENTER.typeId, self.parent.memAddressInput.GetId())),
            ),
            miFollowVal,
        )

        self.PopupMenu(menu, pos)
        menu.Destroy()

    def CenterRow(self, rowIdx):
        """Center the specified row in the view."""
        if not self.data or rowIdx < 0 or rowIdx >= len(self.data):
            return

        visRows = self.GetCountPerPage()
        if visRows <= 0:
            rowH = 15
            rect = self.GetItemRect(0, wx.LIST_RECT_BOUNDS)
            rowH = rect.height if rect and rect.height > 0 else rowH
            clientH = self.GetClientSize().height
            visRows = clientH // rowH

        visRows = min(visRows, len(self.data))
        if visRows <= 0:
            visRows = 15

        anchor = max(0, rowIdx + (visRows // 2))
        maxTop = max(0, len(self.data) - visRows)
        anchor = min(anchor, maxTop)

        self.EnsureVisible(rowIdx)
        self.EnsureVisible(anchor)


class MemDumpListCtrl(wx.ListCtrl):
    def __init__(self, parent):
        super().__init__(parent, style=wx.LC_REPORT | wx.LC_SINGLE_SEL)
        self.InsertColumn(0, "Address", width=170)
        self.InsertColumn(1, "Hex Dump", width=300)
        self.InsertColumn(2, "Ascii", width=170)
        self.data = []

    def UpdateData(self, data):
        """Populate the list control from a string of lines."""
        self.DeleteAllItems()
        self.data.clear()

        for i, line in enumerate(data.splitlines()):
            parts = [p.strip() for p in line.split(",", 1)]
            if not parts:
                continue

            addr = parts[0]
            hexStr = parts[1] if len(parts) > 1 else ""
            asciiChars = []
            for byteToken in hexStr.split():
                try:
                    val = int(byteToken, 16)
                    asciiChars.append(chr(val) if 32 <= val < 127 else ".")
                except ValueError:
                    asciiChars.append(".")

            asciiStr = "".join(asciiChars)
            self.data.append((addr, hexStr, asciiStr))
            idx = self.InsertItem(i, addr)
            self.SetItem(idx, 1, hexStr)
            self.SetItem(idx, 2, asciiStr)

    def GetFirstHexAddress(self):
        """Return the address string from the first row, or None if empty."""
        return self.data[0][0] if self.data else None


class CommandPipeHandler:
    """Handles messages received on the command pipe from the debug server."""

    def __init__(self, console):
        self.console = console

    def _handle_break(self, data):
        with self.console.breakCondition:
            if data:
                self.console.debuggerResponse = data
                self.console.breakCondition.notify_all()
            if not self.console.pendingCommand:
                notified = self.console.breakCondition.wait_for(lambda: self.console.pendingCommand is not None, timeout=TIMEOUT)
                if not notified:
                    self.console.pendingCommand = None
                    return b":TIMEOUT"
                command = self.console.pendingCommand
                self.console.pendingCommand = None
                return command
            return None

    def _handle_dbgcmd(self, data):
        cmd, _ = data.split(b":", 1)
        with self.console.breakCondition:
            if cmd == b"INIT" and not self.console.connected:
                notified = self.console.breakCondition.wait_for(lambda: self.console.debuggerResponse, timeout=TIMEOUT)
                if notified:
                    response = b":" + self.console.debuggerResponse
                    self.console.debuggerResponse = None
                    return response
                else:
                    return b":TIMEOUT"
            else:
                self.console.pendingCommand = data
                self.console.breakCondition.notify_all()
                notified = self.console.breakCondition.wait_for(lambda: self.console.debuggerResponse is not None, timeout=TIMEOUT)
                if not notified:
                    self.console.pendingCommand = None
                    return b":TIMEOUT"

                response = b":" + self.console.debuggerResponse
                if cmd:
                    response = cmd + response

                self.console.debuggerResponse = None
                return response

    def dispatch(self, data):
        response = b":NOPE"
        if not data or b":" not in data:
            log.critical("[DEBUG CONSOLE] Unknown command received from the debug server: %s", data.strip())
        else:
            command, arguments = data.strip().split(b":", 1)
            # log.info((command, data, "console dispatch"))
            fn = getattr(self, f"_handle_{command.lower().decode()}", None)
            if not fn:
                log.critical("[DEBUG CONSOLE] Unknown command received from the debug server: %s", data.strip())
            else:
                try:
                    response = fn(arguments)
                    log.info(response)
                except Exception as e:
                    log.error(e, exc_info=True)
                    log.exception(
                        "[DEBUG CONSOLE] Pipe command handler exception (command %s args %s)",
                        command,
                        arguments,
                    )
        return response


class DebugConsole:
    """Manages launching the debug console window and communication with the debug server via a named pipe."""

    def __init__(self, parent, title, windowPosition, windowSize):
        self.parent = parent
        self.title = title
        self.windowPosition = windowPosition
        self.windowSize = windowSize
        self.pipe = r"\\.\pipe\debugger_pipe"
        self.frame = None

        # These shared condition variables and buffers are used by the pipe handler.
        self.breakCondition = threading.Condition()
        self.pendingCommand = None
        self.lastCommand = None
        self.debuggerResponse = None
        self.commandPipe = None
        self.connected = False

    def OpenConsole(self):
        """Creates (but does not show) the console window."""
        self.frame = ConsoleFrame(self, self.title, self.windowPosition, self.windowSize)
        self.frame.Hide()

    def launch(self):
        """Starts the pipe server and waits for a connection from the debug server."""
        self.commandPipe = PipeServer(
            PipeDispatcher,
            self.pipe,
            message=True,
            dispatcher=CommandPipeHandler(self),
        )
        self.commandPipe.daemon = True
        self.commandPipe.start()
        log.info("[DEBUG CONSOLE] Console pipe server started.")
        self.OpenConsole()
        log.info("[DEBUG CONSOLE] Console launched.")

    def shutdown(self):
        """Gracefully shuts down the debug console and disconnects any open pipes."""
        if self.frame:
            self.frame.Close()
        disconnect_pipes()


class ConsoleFrame(wx.Frame):
    def __init__(self, parent, title, window_position, window_size):
        super().__init__(None, title=title, pos=window_position, size=window_size)
        self.parent = parent
        self.pipe = parent.pipe
        self.panel = ConsolePanel(self)
        self.Bind(wx.EVT_CLOSE, self.OnClose)

        self.ID_STEP_INTO = wx.NewIdRef()
        self.ID_STEP_OVER = wx.NewIdRef()
        self.ID_CONTINUE = wx.NewIdRef()

        accels = wx.AcceleratorTable(
            [
                (wx.ACCEL_NORMAL, wx.WXK_F7, self.ID_STEP_INTO),
                (wx.ACCEL_NORMAL, wx.WXK_F8, self.ID_STEP_OVER),
                (wx.ACCEL_NORMAL, wx.WXK_F10, self.ID_CONTINUE),
            ]
        )
        self.SetAcceleratorTable(accels)
        self.Bind(wx.EVT_MENU, lambda evt: self.panel.SendCommand("S"), id=self.ID_STEP_INTO)
        self.Bind(wx.EVT_MENU, lambda evt: self.panel.SendCommand("O"), id=self.ID_STEP_OVER)
        self.Bind(wx.EVT_MENU, lambda evt: self.panel.SendCommand("C"), id=self.ID_CONTINUE)

    def OnClose(self, event):
        """Handles window close event gracefully."""
        self.panel.ShutdownConsole()
        self.Destroy()


class ConsolePanel(wx.Panel):
    """A wxPython panel that supports multi-threaded debugging with labeled sections, hotkeys, and logging."""

    # Command constants
    CMD_PAGE_MAP = "P"
    CMD_PAGE_LOAD = "I"
    CMD_REG_UPDATE = "R"
    CMD_MEM_DUMP = "M"
    CMD_STACK_UPDATE = "K"
    CMD_EXECUTION = ("O", "S")
    CMD_CONSOLE = ("C", "B", "D")

    def __init__(self, parent):
        super().__init__(parent)
        self.parent = parent
        self.pipe = parent.pipe
        self.pipeHandle = None
        self.connected = self.parent.parent.connected
        self.readLock = threading.Lock()
        self.slotCount = 512
        self.prevHighlight = None
        self.initMemdmp = True
        self.ipVal = None
        self.InitGUI()
        wx.CallLater(100, self.InitPipe)

    def InitGUI(self):
        # Main Layout
        MAX_BTN_W = 120
        mainSizer = wx.BoxSizer(wx.VERTICAL)

        """
        # Threads
        mainSizer.Add(wx.StaticText(self, label="Active Threads"), 0, wx.ALL, 5)
        self.thread_list = wx.ListBox(self)
        mainSizer.Add(self.thread_list, 1, wx.EXPAND | wx.ALL, 5)
        self.thread_list.Bind(wx.EVT_LISTBOX, self.switch_thread)

        # Breakpoints
        mainSizer.Add(wx.StaticText(self, label="Breakpoints"), 0, wx.ALL, 5)
        self.breakpoints_list = wx.ListBox(self)
        mainSizer.Add(self.breakpoints_list, 1, wx.EXPAND | wx.ALL, 5)
        self.breakpoints_list.Bind(wx.EVT_LISTBOX_DCLICK, self.breakpoint)
        """

        fontCourier = wx.Font(10, wx.FONTFAMILY_MODERN, wx.FONTSTYLE_NORMAL, wx.FONTWEIGHT_NORMAL)
        topSizer = wx.BoxSizer(wx.HORIZONTAL)

        # Console Output
        consoleSizer = wx.BoxSizer(wx.VERTICAL)
        consoleSizer.Add(wx.StaticText(self, label="Disassembly Console"), 0, wx.ALL, 5)
        self.disassemblyConsole = DisassemblyListCtrl(self, bits=64)
        self.disassemblyConsole.SetFont(fontCourier)
        consoleSizer.Add(self.disassemblyConsole, 2, wx.EXPAND | wx.ALL, 5)
        topSizer.Add(consoleSizer, 7, wx.EXPAND)

        # Registers
        regsSizer = wx.BoxSizer(wx.VERTICAL)
        regsSizer.Add(wx.StaticText(self, label="Registers"), 0, wx.ALL, 5)
        self.regsDisplay = RegsTextCtrl(self, style=wx.TE_MULTILINE | wx.TE_READONLY)
        self.regsDisplay.SetFont(fontCourier)
        regsSizer.Add(self.regsDisplay, 1, wx.EXPAND | wx.ALL, 5)
        topSizer.Add(regsSizer, 3, wx.EXPAND)

        mainSizer.Add(topSizer, 1, wx.EXPAND)

        bottomSizer = wx.BoxSizer(wx.HORIZONTAL)

        # Memory Dump
        memSizer = wx.BoxSizer(wx.VERTICAL)
        memSizer.Add(wx.StaticText(self, label="Memory Dump"), 0, wx.ALL, 5)
        self.memDumpDisplay = MemDumpListCtrl(self)
        self.memDumpDisplay.SetFont(fontCourier)
        memSizer.Add(self.memDumpDisplay, 2, wx.EXPAND | wx.ALL, 5)

        # Address input field
        memSizer.Add(wx.StaticText(self, label="Memory Dump Address:"), 0, wx.LEFT | wx.TOP, 5)
        self.memAddressInput = wx.TextCtrl(self, style=wx.TE_PROCESS_ENTER)
        self.memAddressInput.SetFont(fontCourier)
        memSizer.Add(self.memAddressInput, 0, wx.EXPAND | wx.ALL, 5)
        self.memAddressInput.Bind(wx.EVT_TEXT_ENTER, self.OnAddressEnter)
        bottomSizer.Add(memSizer, 5, wx.EXPAND)

        # Stack
        stackSizer = wx.BoxSizer(wx.VERTICAL)
        stackSizer.Add(wx.StaticText(self, label="Stack"), 0, wx.ALL, 5)
        self.stackDisplay = StackListCtrl(self)
        self.stackDisplay.SetFont(fontCourier)

        stackSizer.Add(self.stackDisplay, 1, wx.EXPAND | wx.ALL, 5)
        bottomSizer.Add(stackSizer, 5, wx.EXPAND)
        mainSizer.Add(bottomSizer, 1, wx.EXPAND)

        # Debugging Controls
        debugButtons = wx.BoxSizer(wx.HORIZONTAL)
        self.stepIntoBtn = wx.Button(self, label="Step Into (F7)")
        self.stepOverBtn = wx.Button(self, label="Step Over (F8)")
        self.continueBtn = wx.Button(self, label="Continue (F10)")
        for btn, cmd in (
            (self.stepIntoBtn, "S"),
            (self.stepOverBtn, "O"),
            (self.continueBtn, "C"),
        ):
            btn.SetMinSize(wx.Size(MAX_BTN_W, -1))
            btn.Bind(wx.EVT_BUTTON, lambda evt, c=cmd: self.SendCommand(c))
            debugButtons.Add(btn, 0, wx.ALL | wx.ALIGN_CENTER_VERTICAL, 5)

        debugButtons.AddStretchSpacer()
        mainSizer.Add(debugButtons, 0, wx.EXPAND | wx.LEFT | wx.RIGHT | wx.BOTTOM, 5)

        # Console box
        self.outputConsole = wx.TextCtrl(self, style=wx.TE_MULTILINE | wx.TE_READONLY)
        self.outputConsole.SetFont(fontCourier)
        charH = self.outputConsole.GetCharHeight()
        self.outputConsole.SetMinSize(wx.Size(-1, charH * 3))
        mainSizer.Add(wx.StaticText(self, label="Console Output"), 0, wx.LEFT | wx.TOP, 5)
        mainSizer.Add(self.outputConsole, 0, wx.EXPAND | wx.ALL, 5)

        # Input box
        inputSizer = wx.BoxSizer(wx.HORIZONTAL)
        inputSizer.Add(wx.StaticText(self, label="Command Input"), 0, wx.LEFT | wx.ALIGN_CENTER_VERTICAL, 5)
        self.inputBox = wx.TextCtrl(self, style=wx.TE_PROCESS_ENTER)
        self.inputBox.Bind(wx.EVT_TEXT_ENTER, self.OnEnter)
        inputSizer.Add(self.inputBox, 1, wx.EXPAND | wx.LEFT | wx.RIGHT, 5)
        inputSizer.AddStretchSpacer(1)

        # Status Bar
        self.statusBar = wx.StaticText(self, label="Status: Disconnected")
        inputSizer.Add(self.statusBar, 0, wx.RIGHT | wx.ALIGN_CENTER_VERTICAL, 5)

        mainSizer.Add(inputSizer, 0, wx.EXPAND)

        self.SetSizer(mainSizer)

    def OnKeyDown(self, event):
        if self.FindFocus() == self.inputBox:
            event.Skip()
            return

        if self.FindFocus() == self.memAddressInput:
            event.Skip()
            return

        if event.GetKeyCode() == wx.WXK_F7 and event.ControlDown():
            self.SendCommand("S")
        elif event.GetKeyCode() == wx.WXK_F8 and event.ControlDown():
            self.SendCommand("O")
        elif event.GetKeyCode() == wx.WXK_F10 and event.ControlDown():
            self.SendCommand("C")
        else:
            event.Skip()

    def OnAddressEnter(self, event):
        self.memAddr = self.memAddressInput.GetValue().strip()
        if self.memAddr:
            self.SendCommand("M", self.memAddr)

        self.memAddressInput.Clear()
        event.Skip()

    def AppendConsole(self, text):
        """Appends text to the output console."""
        self.outputConsole.AppendText(text + "\n")

    def UpdateRegs(self, text):
        """Update registers display."""
        self.regsDisplay.Clear()
        regsText = self.regsDisplay.GetValue()
        m = re.search(r"\b([ER]IP):\s*([0-9A-Fa-f]+)", regsText)
        self.ipVal = m.group(2) if m else None
        self.regsDisplay.SetValue(text)

    def UpdateStack(self, data):
        """Update stack display."""
        self.stackDisplay.UpdateData(data)

    def UpdateMemDump(self, data):
        """Update memory dump display."""
        self.memDumpDisplay.UpdateData(data)

    def UpdateStatus(self, status):
        self.statusBar.SetLabel(status)

    def InitPipe(self):
        try:
            self.pipeHandle = win32file.CreateFile(
                self.pipe,
                win32file.GENERIC_READ | win32file.GENERIC_WRITE,
                0,
                None,
                win32file.OPEN_EXISTING,
                0,
                None,
            )
            log.info("[DEBUG CONSOLE] Console connected to named pipe.")
            self.SendInit()
        except Exception as e:
            log.error("[DEBUG CONSOLE] Console failed to connect to named pipe: %s", e)

    def SendInit(self):
        if self.pipeHandle:
            log.info("[DEBUG CONSOLE] Sending init command...")
            threading.Thread(target=self.SendCommand, args=("init",), daemon=True).start()
        else:
            wx.CallLater(100, self.SendInit)

    def ReadResponse(self):
        """Reads a full response from the pipe in a thread-safe manner."""
        with self.readLock:
            try:
                # Read up to BUFFER_SIZE bytes; adjust if needed.
                result, data = win32file.ReadFile(self.pipeHandle, BUFFER_SIZE)
                response = data.decode("utf-8").strip()
                return response
            except Exception as e:
                log.error("[DEBUG CONSOLE] Reading response: %s", e)
                return ""

    def WaitForResponse(self):
        """Waits for a response and then updates the GUI (called in a background thread)."""
        response = self.ReadResponse()
        wx.CallAfter(self.ProcessServerOutput, response)

    def SendCommand(self, command, data=""):
        if command.lower() != "init" and (not self.connected or not self.pipeHandle):
            log.error("[DEBUG CONSOLE] Cannot send command: Not connected to pipe")
            return

        fullCommand = f"{DBGCMD}:{command.upper()}:{data}".encode("utf-8") + b"\n"
        overlapped = pywintypes.OVERLAPPED()
        overlapped.hEvent = win32event.CreateEvent(None, 0, 0, None)
        try:
            win32file.WriteFile(self.pipeHandle, fullCommand, overlapped)
        except pywintypes.error as e:
            log.error(f"[DEBUG CONSOLE] Pipe write error: {e}")
        finally:
            if overlapped.hEvent:
                win32file.CloseHandle(overlapped.hEvent)

        threading.Thread(target=self.WaitForResponse, daemon=True).start()

    def OnEnter(self, event):
        """Handles user input and processes commands."""
        inputText = self.inputBox.GetValue().strip()
        try:
            cmd, data = inputText.split(" ", 1)
        except ValueError:
            cmd = inputText
            data = ""

        cmd = cmd.lower()
        if cmd == "disconnect":
            wx.CallAfter(self.statusBar.SetLabel, "Status: Disconnected")
            win32file.CloseHandle(self.pipeHandle)
            self.connected = False
            log.info("[DEBUG CONSOLE] Pipe disconnected successfully.")
        elif cmd == "quit":
            self.SendCommand("C")
            self.ShutdownConsole()
        elif cmd == "clear":
            self.outputConsole.Clear()
        elif cmd in ("", "h"):
            pass
        elif cmd == "b":
            try:
                reg, addr = data.split(" ", 1)
                data = "|".join([reg, addr])
                self.SendCommand(cmd, data)
            except ValueError:
                self.outputConsole.AppendText("Invalid command: B <register> <address>")
        elif cmd == "d":
            self.SendCommand(cmd, data)
        else:
            self.SendCommand(cmd)

        self.inputBox.Clear()
        event.Skip()

    def ShutdownConsole(self):
        """Handles graceful shutdown of the console."""
        self.close()
        self.parent.Close()

    def close(self):
        """Stops the reading thread."""
        self.connected = False
        if self.pipeHandle:
            win32file.CloseHandle(self.pipeHandle)
            self.pipeHandle = None
            log.info("[DEBUG CONSOLE] Pipe handle closed")

    def RefreshViewState(self):
        self.SendCommand("R")
        if self.initMemdmp:
            self.SendCommand("M")
            self.initMemdmp = False
        else:
            addr = self.memDumpDisplay.GetFirstHexAddress()
            self.memAddressInput.SetValue(addr)
            self.OnAddressEnter(wx.CommandEvent(wx.EVT_TEXT_ENTER.typeId, self.memAddressInput.GetId()))
        self.SendCommand("K")

    def HandleConnection(self, payload):
        """Handle initial connection logic."""
        self.connected = True
        self.UpdateStatus("Status: Connected")
        if not self.parent.IsShown():
            self.parent.Show()
            self.parent.Layout()
        self.AppendConsole(payload)
        self.disassemblyConsole.RequestPageMap()

    def DispatchCommand(self, command, payload):
        wx.CallAfter(self._DispatchCommand, command, payload)

    def _DispatchCommand(self, command, payload):
        """Dispatch commands to their respective handlers."""
        handlers = {
            self.CMD_PAGE_MAP: self.HandlePageMap,
            self.CMD_PAGE_LOAD: self.HandlePageLoad,
            self.CMD_REG_UPDATE: self.HandleRegUpdate,
            self.CMD_MEM_DUMP: self.HandleMemDump,
            self.CMD_STACK_UPDATE: self.HandleStackUpdate,
        }

        if command in self.CMD_CONSOLE:
            self.HandleConsoleOutput(payload)
            return

        if command in self.CMD_EXECUTION:
            self.HandleExecution(payload)
            return

        handler = handlers.get(command)
        if handler:
            handler(payload)
        else:
            log.warning("[DEBUG CONSOLE] Unknown command '%s' received", command)

    def HandlePageMap(self, payload):
        self.disassemblyConsole.LoadPageMap(payload)
        self.disassemblyConsole.RequestDecodeSync(self.disassemblyConsole.currentRip)

    def HandlePageLoad(self, payload):
        self.disassemblyConsole.LoadPage(payload)
        self.disassemblyConsole.RequestDecodeSync(self.disassemblyConsole.currentRip)
        self.RefreshViewState()

    def HandleRegUpdate(self, payload):
        self.UpdateRegs(payload)
        if self.ipVal:
            self.disassemblyConsole.currentRip = self.ipVal
        self.disassemblyConsole.RequestDecodeSync(self.disassemblyConsole.currentRip)

    def HandleMemDump(self, payload):
        self.UpdateMemDump(payload)

    def HandleStackUpdate(self, payload):
        self.UpdateStack(payload)

    def HandleConsoleOutput(self, payload):
        self.AppendConsole(payload)

    def HandleExecution(self, payload):
        """Handle execution commands (O, S) by parsing CIP and updating disassembly."""
        m = re.search(r"0x[0-9a-fA-F]+", payload)
        if m:
            cip = int(m.group(0), 16)
            self.disassemblyConsole.currentRip = cip
            self.AppendConsole(payload)
            self.disassemblyConsole.RequestDecodeSync(self.disassemblyConsole.currentRip)
            self.RefreshViewState()
        else:
            log.error("[DEBUG CONSOLE] Failed to parse CIP from payload: %s", payload)

    def ProcessServerOutput(self, data):
        wx.CallAfter(self._ProcessServerOutput, data)

    def _ProcessServerOutput(self, data):
        """Process server output by parsing command and payload, then dispatching."""
        if not data or ":" not in data:
            log.error("[DEBUG CONSOLE] Invalid data format: %s", data)
            return

        try:
            command, payload = data.split(":", 1)
        except ValueError:
            log.error("[DEBUG CONSOLE] Failed to parse data: %s", data)
            return

        if not self.connected and payload:
            m = re.search(r"0x[0-9a-fA-F]+", payload)
            if m:
                cip = int(m.group(0), 16)
                self.disassemblyConsole.bits = 64 if cip > 0xFFFFFFFF else 32
                self.disassemblyConsole.currentRip = cip
                log.debug("[DEBUG CONSOLE] Detected CIP=0x%x, setting bits=%d", cip, self.disassemblyConsole.bits)

            self.HandleConnection(payload)
            return

        if not command or not payload:
            log.error("[DEBUG CONSOLE] Empty command = '%s' or payload = '%s'", command, payload)
            return

        self.DispatchCommand(command, payload)
