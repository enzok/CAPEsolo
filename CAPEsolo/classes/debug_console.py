import logging
import re
import threading
import time
from collections import namedtuple
from typing import Dict, List, Optional, Tuple

import pywintypes
import win32event
import win32file
import wx
from capstone import CS_ARCH_X86, CS_MODE_32, CS_MODE_64, Cs, CsError

from CAPEsolo.lib.common.defines import PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE, PAGE_READONLY, PAGE_READWRITE
from CAPEsolo.lib.core.pipe import PipeDispatcher, PipeServer, disconnect_pipes

log = logging.getLogger(__name__)

TIMEOUT = 6000
PAGE_SIZE = 0x1000
BUFFER_SIZE = 0x10000
CHUNK_SIZE = BUFFER_SIZE // 2
DBGCMD = "DBGCMD"
READABLE_FLAGS = PAGE_READONLY | PAGE_READWRITE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE
COLOR_LIGHT_YELLOW = wx.Colour(255, 255, 150)

DecodedInstruction = namedtuple("DecodedInstruction", ["address", "bytes", "text"])


class DisassemblyListCtrl(wx.ListCtrl):
    def __init__(self, parent):
        super().__init__(parent, style=wx.LC_REPORT)
        self.parent = parent
        self.InsertColumn(0, "Address", width=150)
        self.InsertColumn(1, "Hex bytes", width=180)
        self.InsertColumn(2, "Disassembly", width=340)
        self.pageMap: List[Tuple[int, int, int]] = []
        self.decodeCache: List[DecodedInstruction] = []
        self.cacheLock = threading.Lock()
        self.pendingPageBase: Optional[int] = None
        self.Bind(wx.EVT_CONTEXT_MENU, self.OnContextMenu)

    def LoadPageMap(self, data: str):
        if not data:
            return

        self.pageMap.clear()
        for entry in data.split("|"):
            if not entry:
                continue

            try:
                base, size, protect = entry.split(",")
                baseAddr = int(base, 16)
                regionSize = int(size)
                protect = int(protect, 16)
                self.pageMap.append((baseAddr, regionSize, protect))
            except (ValueError, AttributeError) as e:
                log.error("[DEBUG CONSOLE] Failed to parse entry '%s': %s", entry, e)
                continue

        self.pageMap.sort(key=lambda x: x[0])

    def FindPage(self, addr: int) -> Optional[Tuple[int, int, int]]:
        for base, size, prot in self.pageMap:
            if base <= addr < base + size and (prot & READABLE_FLAGS):
                return base, size, prot

        log.warning("[DEBUG CONSOLE] Address: 0x%x not in any page", addr)
        return None

    def RequestPage(self, pageBase: int):
        with self.cacheLock:
            self.pendingPageBase = pageBase
        self.parent.SendCommand(ConsolePanel.CMD_PAGE_LOAD, hex(pageBase))

    def SetInstructions(self, insts: List[DecodedInstruction]):
        self.Freeze()
        try:
            with self.cacheLock:
                self.decodeCache = insts
                self.DeleteAllItems()
                for i, inst in enumerate(insts):
                    idx = self.InsertItem(i, f"{inst.address:#010X}")
                    self.SetItem(idx, 1, inst.bytes.hex().upper())
                    self.SetItem(idx, 2, inst.text.upper())
                    mnemonic = inst.text.split()[0].lower()
                    if mnemonic == "call":
                        self.SetItemTextColour(idx, wx.BLUE)
                    elif mnemonic in ("jmp", "je", "jne", "jg", "jl"):
                        self.SetItemTextColour(idx, wx.GREEN)
        finally:
            self.Thaw()

        cipIndex = self.GetCipIndex()
        if cipIndex:
            self.HighlightIp(cipIndex)

    def GetCipIndex(self, cip=None):
        cipIndex = -1
        if not cip:
            cip = self.parent.cip
        if cip is None:
            return

        with self.cacheLock:
            for i, inst in enumerate(self.decodeCache):
                if inst.address == cip:
                    cipIndex = i
                    break

        return cipIndex

    def HighlightIp(self, index):
        if index >= 0:
            for i in range(self.GetItemCount()):
                self.SetItemBackgroundColour(i, wx.Colour(wx.WHITE))

            self.SetItemBackgroundColour(index, wx.Colour(wx.CYAN))
            self.CenterRow(index)
        else:
            log.warning("[DEBUG CONSOLE] CIP %#x not found in decodeCache", self.parent.cip)

        self.Refresh()

    def CenterRow(self, rowIdx):
        """Center the specified row in the view."""
        visRows = self.GetCountPerPage()
        if visRows <= 0:
            rowH = 15
            rect = self.GetItemRect(0, wx.LIST_RECT_BOUNDS)
            rowH = rect.height if rect and rect.height > 0 else rowH
            clientH = self.GetClientSize().height
            visRows = clientH // rowH

        visRows = min(visRows, len(self.decodeCache))
        if visRows <= 0:
            visRows = 15

        anchor = max(0, rowIdx + (visRows // 2))
        maxTop = max(0, len(self.decodeCache) - visRows)
        anchor = min(anchor, maxTop)

        self.EnsureVisible(rowIdx)
        self.EnsureVisible(anchor)

    def OnContextMenu(self, event):
        pos = event.GetPosition()
        pos = self.ScreenToClient(pos)
        idx, flags = self.HitTest(pos)
        if idx == wx.NOT_FOUND:
            return

        menu = wx.Menu()
        miCopy = menu.Append(wx.ID_ANY, "Copy")
        miGoTo = menu.Append(wx.ID_ANY, "Go To")
        miGoToSelected = menu.Append(wx.ID_ANY, "Go To Selected Address")
        miGoToCIP = menu.Append(wx.ID_ANY, "Go To CIP")
        miRunTo = menu.Append(wx.ID_ANY, "Run To")

        menu.Bind(wx.EVT_MENU, lambda e: self.OnCopy(idx), miCopy)
        menu.Bind(wx.EVT_MENU, self.OnGoTo, miGoTo)
        menu.Bind(wx.EVT_MENU, lambda e: self.OnGoToSelected(idx), miGoToSelected)
        menu.Bind(wx.EVT_MENU, self.OnGoToCIP, miGoToCIP)
        menu.Bind(wx.EVT_MENU, lambda e: self.OnRunTo(idx), miRunTo)
        self.PopupMenu(menu, pos)
        menu.Destroy()

    def OnCopy(self, idx):
        row_text = f"{self.GetItemText(idx, 0)}\t{self.GetItemText(idx, 1)}\t{self.GetItemText(idx, 2)}"
        clipboard = wx.Clipboard()
        if clipboard.Open():
            try:
                clipboard.SetData(wx.TextDataObject(row_text))
            except Exception as e:
                log.error("[DEBUG CONSOLE] Failed to copy to clipboard: %s", e)
            finally:
                clipboard.Close()

    def OnGoTo(self, event):
        dialog = wx.TextEntryDialog(self, "Enter hex address (e.g., 0x12345678):", "Go To Address", "0x")
        if dialog.ShowModal() == wx.ID_OK:
            addr_str = dialog.GetValue().strip()
            try:
                addr = int(addr_str, 16)
                cipIndex = self.GetCipIndex(addr)
                self.HighlightIp(cipIndex)
            except ValueError as e:
                log.error("[DEBUG CONSOLE] Invalid hex address: %s (%s)", addr_str, e)
                wx.MessageBox(f"Invalid hex address: {addr_str}", "Error", wx.OK | wx.ICON_ERROR)
        dialog.Destroy()

    def OnGoToSelected(self, idx):
        addr_str = self.GetItemText(idx, 0).strip()
        try:
            addr = int(addr_str, 16)
            cipIndex = self.GetCipIndex(addr)
            self.HighlightIp(cipIndex)
        except ValueError as e:
            log.error("[DEBUG CONSOLE] Invalid selected address: %s (%s)", addr_str, e)
            wx.MessageBox(f"Invalid selected address: {addr_str}", "Error", wx.OK | wx.ICON_ERROR)

    def OnGoToCIP(self, event):
        cipIndex = self.GetCipIndex(self.parent.cip)
        self.HighlightIp(cipIndex)

    def OnRunTo(self, idx):
        addrStr = self.GetItemText(idx, 0).strip()
        try:
            addr = int(addrStr, 16)
            payload = f"{addr:#X}"
            self.parent.SendCommand("T", payload)
        except ValueError as e:
            log.error("[DEBUG CONSOLE] Invalid address for Run To: %s (%s)", addrStr, e)
            wx.MessageBox(f"Invalid address for Run To: {addrStr}", "Error", wx.OK | wx.ICON_ERROR)

class RegsTextCtrl(wx.TextCtrl):
    def __init__(self, parent, style):
        """TextCtrl subclass"""
        super().__init__(parent, style=style)
        self.parent = parent
        self.Bind(wx.EVT_CONTEXT_MENU, self.OnContextMenu)

    def OnContextMenu(self, event):
        menu = wx.Menu()
        miFollow = menu.Append(wx.ID_ANY, "Dump Value")
        miClearZeroFlag = menu.Append(wx.ID_ANY, "Clear Zero Flag")
        miSetZeroFlag = menu.Append(wx.ID_ANY, "Set Zero Flag")
        miFlipZeroFlag = menu.Append(wx.ID_ANY, "Flip Zero Flag")
        miClearSignFlag = menu.Append(wx.ID_ANY, "Clear Sign Flag")
        miSetSignFlag = menu.Append(wx.ID_ANY, "Set Sign Flag")
        miFlipSignFlag = menu.Append(wx.ID_ANY, "Flip Sign Flag")
        miClearCarryFlag = menu.Append(wx.ID_ANY, "Clear Carry Flag")
        miSetCarryFlag = menu.Append(wx.ID_ANY, "Set Carry Flag")
        miFlipCarryFlag = menu.Append(wx.ID_ANY, "Flip Carry Flag")

        menu.Bind(wx.EVT_MENU, self.OnFollowValue, miFollow)
        menu.Bind(wx.EVT_MENU, self.ClearZeroFlag, miClearZeroFlag)
        menu.Bind(wx.EVT_MENU, self.SetZeroFlag, miSetZeroFlag)
        menu.Bind(wx.EVT_MENU, self.FlipZeroFlag, miFlipZeroFlag)
        menu.Bind(wx.EVT_MENU, self.ClearSignFlag, miClearSignFlag)
        menu.Bind(wx.EVT_MENU, self.SetSignFlag, miSetSignFlag)
        menu.Bind(wx.EVT_MENU, self.FlipSignFlag, miFlipSignFlag)
        menu.Bind(wx.EVT_MENU, self.ClearCarryFlag, miClearCarryFlag)
        menu.Bind(wx.EVT_MENU, self.SetCarryFlag, miSetCarryFlag)
        menu.Bind(wx.EVT_MENU, self.FlipCarryFlag, miFlipCarryFlag)

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

    def ClearZeroFlag(self, event):
        self.FlagCommand("ClearZeroFlag")

    def SetZeroFlag(self, event):
        self.FlagCommand("SetZeroFlag")

    def FlipZeroFlag(self, event):
        self.FlagCommand("FlipZeroFlag")

    def ClearSignFlag(self, event):
        self.FlagCommand("ClearSignFlag")

    def SetSignFlag(self, event):
        self.FlagCommand("SetSignFlag")

    def FlipSignFlag(self, event):
        self.FlagCommand("FlipSignFlag")

    def ClearCarryFlag(self, event):
        self.FlagCommand("ClearCarryFlag")

    def SetCarryFlag(self, event):
        self.FlagCommand("SetCarryFlag")

    def FlipCarryFlag(self, event):
        self.FlagCommand("FlipCarryFlag")

    def FlagCommand(self, cmd):
        self.parent.SendCommand("E", cmd)
        self.parent.SendCommand("K")


class StackListCtrl(wx.ListCtrl):
    def __init__(self, parent):
        super().__init__(parent, style=wx.LC_REPORT | wx.LC_SINGLE_SEL)
        self.parent = parent
        self.spVal = None
        self.InsertColumn(0, "Address", width=170)
        self.InsertColumn(1, "Value", width=170)
        self.InsertColumn(2, "", width=70)
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
                self.SetItemBackgroundColour(i, COLOR_LIGHT_YELLOW)

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
        miFollowAddr = menu.Append(wx.ID_ANY, "Dump Address")
        miFollowVal = menu.Append(wx.ID_ANY, "Dump Value")

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
        self.InsertColumn(1, "Hex Dump", width=400)
        self.InsertColumn(2, "Ascii", width=150)
        self.data = []
        self.Bind(wx.EVT_CONTEXT_MENU, self.OnContextMenu)

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

    def OnContextMenu(self, event):
        pos = event.GetPosition()
        pos = self.ScreenToClient(pos)
        idx, flags = self.HitTest(pos)
        if idx == wx.NOT_FOUND:
            return

        menu = wx.Menu()
        miCopy = menu.Append(wx.ID_ANY, "Copy")
        menu.Bind(wx.EVT_MENU, lambda e: self.OnCopy(idx), miCopy)
        self.PopupMenu(menu, pos)
        menu.Destroy()

    def OnCopy(self, idx):
        row_text = f"{self.GetItemText(idx, 0)}\t{self.GetItemText(idx, 1)}\t{self.GetItemText(idx, 2)}"
        clipboard = wx.Clipboard()
        if clipboard.Open():
            try:
                clipboard.SetData(wx.TextDataObject(row_text))
            except Exception as e:
                log.error("[DEBUG CONSOLE] Failed to copy to clipboard: %s", e)
            finally:
                clipboard.Close()

class CommandPipeHandler:
    """Handles messages received on the command pipe from the debug server."""

    def __init__(self, console):
        self.console = console
        self.connected = False

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
            if cmd == b"INIT" and not self.connected:
                notified = self.console.breakCondition.wait_for(lambda: self.console.debuggerResponse, timeout=TIMEOUT)
                if notified:
                    response = b"INIT:" + self.console.debuggerResponse
                    self.console.debuggerResponse = None
                    self.connected = True
                    return response
                else:
                    self.console.debuggerResponse = None
                    return b":TIMEOUT"

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
                    if response.decode("ascii")[0] not in ("M", "R", "K", "I"):
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
    CMD_CONTINUE = "C"
    CMD_BREAKPOINT = "B"
    CMD_PAGE_LOAD = "I"
    CMD_STACK_UPDATE = "K"
    CMD_MEM_DUMP = "M"
    CMD_PAGE_MAP = "P"
    CMD_REG_UPDATE = "R"
    CMD_EXECUTION = ("O", "S", "T")
    CMD_CONSOLE = ("D")

    def __init__(self, parent):
        super().__init__(parent)
        self.parent = parent
        self.pipe = parent.pipe
        self.pipeHandle = None
        self.connected = False
        self.readLock = threading.Lock()
        self.slotCount = 512
        self.prevHighlight = None
        self.initMemdmp = True
        self.cip = None
        self.bits = 64
        self.pageBuffers: Dict[int, bytes] = {}
        self.requestedPages = set()
        self.pendingPageRange = None
        self.forceNextJump = False
        self.pageLock = threading.Lock()
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
        self.disassemblyConsole = DisassemblyListCtrl(self)
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
        bottomSizer.Add(memSizer, 7, wx.EXPAND)

        # Stack
        stackSizer = wx.BoxSizer(wx.VERTICAL)
        stackSizer.Add(wx.StaticText(self, label="Stack"), 0, wx.ALL, 5)
        self.stackDisplay = StackListCtrl(self)
        self.stackDisplay.SetFont(fontCourier)
        stackSizer.Add(self.stackDisplay, 1, wx.EXPAND | wx.ALL, 5)
        bottomSizer.Add(stackSizer, 3, wx.EXPAND)

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
        self.regsDisplay.SetValue(text)
        regsText = self.regsDisplay.GetValue()
        m = re.search(r"\b([ER]IP):\s*([0-9A-Fa-f]+)", regsText)
        self.cip = int(m.group(2), 16) if m else None

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
        if response:
            wx.CallAfter(self.ProcessServerOutput, response)
        else:
            wx.CallLater(100, self.WaitForResponse)

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
            log.error("[DEBUG CONSOLE] Pipe write error: %s", e)
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
        self.SendCommand(self.CMD_REG_UPDATE)
        if self.initMemdmp:
            self.SendCommand(self.CMD_MEM_DUMP)
            self.initMemdmp = False
        else:
            addr = self.memDumpDisplay.GetFirstHexAddress()
            if addr is not None:
                self.memAddressInput.SetValue(addr)
                self.OnAddressEnter(wx.CommandEvent(wx.EVT_TEXT_ENTER.typeId, self.memAddressInput.GetId()))

        self.SendCommand(self.CMD_STACK_UPDATE)

    def DispatchCommand(self, command, payload):
        """Dispatch commands to their respective handlers."""
        handlers = {
            self.CMD_PAGE_MAP: self.HandlePageMap,
            self.CMD_PAGE_LOAD: self.HandlePageLoad,
            self.CMD_REG_UPDATE: self.HandleRegUpdate,
            self.CMD_MEM_DUMP: self.HandleMemDump,
            self.CMD_STACK_UPDATE: self.HandleStackUpdate,
            self.CMD_CONTINUE: self.HandleContinue,
            self.CMD_BREAKPOINT: self.HandleBreakpoint,
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

    def JumpTo(self, address: int):
        """Use pageMap to find aligned page, then load & decode if page is readable."""
        self.cip = address
        region = self.disassemblyConsole.FindPage(address)
        if region is None:
            self.SendCommand(self.CMD_PAGE_MAP)
            return

        regionBase, regionSize, regionProt = region
        regionEnd = regionBase + regionSize
        half = CHUNK_SIZE // 2
        desiredStart = address - half
        desiredEnd = address + half
        bytesBefore = address - regionBase
        bytesAfter = regionEnd - address
        regions = [(regionBase, regionSize, regionProt)]
        sortedPageMap = sorted(self.disassemblyConsole.pageMap, key=lambda x: x[0])
        currentIdx = next(i for i, r in enumerate(sortedPageMap) if r[0] == regionBase)
        if regionSize < CHUNK_SIZE or bytesBefore < half:
            if currentIdx > 0:
                prevRegion = sortedPageMap[currentIdx - 1]
                if prevRegion[2] & READABLE_FLAGS:
                    regions.append(prevRegion)

        if regionSize < CHUNK_SIZE or bytesAfter < half:
            if currentIdx < len(sortedPageMap) - 1:
                nextRegion = sortedPageMap[currentIdx + 1]
                if nextRegion[2] & READABLE_FLAGS:
                    regions.append(nextRegion)

        pages = set()
        for base, size, prot in regions:
            if base > desiredEnd or base + size < desiredStart:
                continue

            firstPage = (base // PAGE_SIZE) * PAGE_SIZE
            lastPage = ((base + size - 1) // PAGE_SIZE) * PAGE_SIZE
            page = firstPage

            while page <= lastPage:
                if desiredStart - PAGE_SIZE <= page <= desiredEnd:
                    pages.add(page)
                page += PAGE_SIZE

        if not pages:
            log.error("[DEBUG CONSOLE] No valid pages found for address %#x", address)
            return

        with self.pageLock:
            if self.requestedPages and not self.forceNextJump:
                return

            self.forceNextJump = False
            self.pageBuffers.clear()
            self.requestedPages.clear()
            self.pendingPageRange = (min(pages), max(pages))
            for page in sorted(pages):
                self.requestedPages.add(page)
                self.disassemblyConsole.RequestPage(page)

        self.RefreshViewState()

    def HandleConnection(self, payload):
        """Handle initial connection logic."""
        self.connected = True
        self.UpdateStatus("Status: Connected")
        if not self.parent.IsShown():
            self.parent.Show()
            self.parent.Layout()
        self.AppendConsole(payload)
        self.disassemblyConsole.LoadPageMap("")
        self.SendCommand(self.CMD_PAGE_MAP)

    def HandleBreakpoint(self, payload):
        self.AppendConsole(payload)
        self.GetCip(payload)

    def HandleContinue(self, payload):
        self.AppendConsole(payload)

    def HandlePageMap(self, payload):
        self.disassemblyConsole.LoadPageMap(payload)
        self.JumpTo(self.cip)

    def HandlePageLoad(self, payload):
        """Process page load response, using pendingPageBase from DisassemblyListCtrl."""
        try:
            requestAddr, pageData = payload.split("|", 1)
            pageBase = int(requestAddr, 16)
        except ValueError as e:
            log.error("[DEBUG CONSOLE] Invalid page load payload format: %s (%s)", payload, str(e))
            return

        try:
            pageData = bytes.fromhex(pageData)
        except ValueError as e:
            log.error("[DEBUG CONSOLE] Invalid hex string in instruction_page: %s", str(e))
            return

        if len(pageData) == 0:
            log.error("[DEBUG CONSOLE] Empty page data for page %#x", pageBase)
            return

        region = self.disassemblyConsole.FindPage(pageBase)
        expectedSize = PAGE_SIZE if region is None else min(PAGE_SIZE, region[1] - (pageBase - region[0]))

        if len(pageData) == 0:
            log.error("[DEBUG CONSOLE] Empty page data for page %#x", pageBase)
            return

        if len(pageData) > expectedSize:
            log.warning("[DEBUG CONSOLE] Page data for %#x exceeds expected size (%d > %d)", pageBase, len(pageData), expectedSize)
            pageData = pageData[:expectedSize]

        with self.pageLock:
            self.pageBuffers[pageBase] = pageData
            self.requestedPages.discard(pageBase)
            complete = not self.requestedPages

        log.debug("[DEBUG CONSOLE] Received page %#x, %d pages remaining", pageBase, len(self.requestedPages))

        if complete:
            self.UpdateDisassemblyView()

    def UpdateDisassemblyView(self):
        """Combine instructions from all requested pages and update the view."""
        with self.pageLock:
            firstPage, lastPage = self.pendingPageRange
            buffers = dict(self.pageBuffers)

        csMode = CS_MODE_64 if self.bits == 64 else CS_MODE_32
        cs = Cs(CS_ARCH_X86, csMode)
        cs.detail = False

        insts: List[DecodedInstruction] = []

        for page in range(firstPage, lastPage + PAGE_SIZE, PAGE_SIZE):
            pageData = buffers.get(page)
            try:
                for ins in cs.disasm(pageData, page):
                    text = f"{ins.mnemonic} {ins.op_str}".strip()
                    insts.append(DecodedInstruction(ins.address, ins.bytes, text))
            except CsError as e:
                log.error("[DEBUG CONSOLE] Capstone error on page %x: %s", page, str(e))
                continue

        log.debug("[DEBUG CONSOLE] Disassembled %d instructions", len(insts))
        insts.sort(key=lambda i: i.address)
        self.disassemblyConsole.SetInstructions(insts)
        self.RefreshViewState()

    def HandleRegUpdate(self, payload):
        self.UpdateRegs(payload)

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
            self.cip = cip
            self.AppendConsole(payload)
            self.JumpTo(cip)
        else:
            log.error("[DEBUG CONSOLE] Failed to parse CIP from payload: %s", payload)

    def GetCip(self, data):
        m = re.search(r"0x[0-9a-fA-F]+", data)
        if m:
            cip = int(m.group(0), 16)
            self.bits = 64 if cip > 0xFFFFFFFF else 32
            self.cip = cip
            # log.debug("[DEBUG CONSOLE] Detected CIP=0x%x, setting bits=%d", cip, self.bits)

    def ProcessServerOutput(self, data):
        """Process server output by parsing command and payload, then dispatching."""
        if not data or ":" not in data:
            log.error("[DEBUG CONSOLE] Invalid data format: %s", data)
            return

        try:
            command, payload = data.split(":", 1)
        except ValueError:
            log.error("[DEBUG CONSOLE] Failed to parse data: %s", data)
            return

        if not command or not payload:
            log.error("[DEBUG CONSOLE] Empty command = '%s' or payload = '%s'", command, payload)
            return

        if command == "INIT" and not self.connected:
            self.GetCip(payload)
            self.HandleConnection(payload)
            return

        self.DispatchCommand(command, payload)
