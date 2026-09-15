import bisect
import logging
import re
import struct
from collections import defaultdict
from contextlib import suppress
from queue import Queue
from threading import Condition, Lock, Thread

import pywintypes
import win32event
import win32file
import wx
from distorm3 import Decode, Decode32Bits, Decode64Bits

from CAPEsolo.capelib.cmdconsts import *
from CAPEsolo.capelib.page_cache import (
    BoundInstructions,
    ContiguousSpan,
    CoversAddress,
    DistantPages,
    FindRegion,
    HotPages,
    PageChanged,
    PageHash,
    PagesOfSpan,
    SelectWindowPages,
)
from CAPEsolo.lib.core.pipe import PipeDispatcher, PipeServer, disconnect_pipes

from .debug_controls import (
    BreakpointDialog,
    BreakpointsListCtrl,
    CallStackListCtrl,
    DecodedInstruction,
    DisassemblyListCtrl,
    IsValidHexAddress,
    MemDumpListCtrl,
    ModulesListCtrl,
    RegsTextCtrl,
    StackListCtrl,
    ThreadListCtrl,
)
from .debug_pipe import CommandPipeHandler
from .patch_assembler import Assembler
from .patch_models import PatchEntry
from .theme import ACCENT_ORANGE, BG_CARD, FONT_CODE, apply_theme

log = logging.getLogger(__name__)

MAX_LEN = 256
PAGE_SIZE = 4 * 1024
BUFFER_SIZE = 65 * 1024
CHUNK_SIZE = BUFFER_SIZE // 2
# Buffered pages kept either side of CIP before eviction, so the retained cache is bounded
# at (2 * KEEP_PAGES + 1) * PAGE_SIZE regardless of how long the session runs.
KEEP_PAGES = 16
# Smallest a splitter pane may be dragged to, so no view can be collapsed out of reach.
MIN_PANE = 80
DBGCMD = "DBGCMD"
# Request tags, sent as a leading "<id>:<purpose>|" field and echoed by capemon in the
# response. Replaces guessing a response's purpose from its length, which could not tell a
# 4-byte pointer read from a 4-byte panel dump, and lets a page load be matched to the
# request that caused it rather than merely counted.
TAG_DUMP = "DUMP"
TAG_FILE = "FILE"
TAG_DEREF = "DEREF"
TAG_STR = "STR"
TAG_STRW = "STRW"
TAG_PAGE = "PAGE"
STALE_MONITOR_MSG = (
    "Untagged debugger response: the monitor is older than this build of CAPEsolo. "
    "Update the monitor dlls."
)
DEBUG_PIPE = r"\\.\pipe\debugger_pipe"
REGISTERS = {
    "RAX",
    "RBX",
    "RCX",
    "RDX",
    "RSI",
    "RDI",
    "RSP",
    "RBP",
    "EAX",
    "EBX",
    "ECX",
    "EDX",
    "ESI",
    "EDI",
    "ESP",
    "EBP",
    "R8",
    "R9",
    "R10",
    "R11",
    "R12",
    "R13",
    "R14",
    "R15",
}
wx.Bell = lambda: None
JMP_CALL_ADDR_RX = re.compile(
    r"\b(?P<mnemonic>jmp|call)\b\s+(?:[A-Za-z_]+\s+)*?(?P<operand>\[[^\]]+\]|0x[0-9A-Fa-f]+)$", re.IGNORECASE
)
LEA_MOV_ADDR_RX = re.compile(r"\b(?P<mnemonic>lea|mov)\b\s+(?P<dest>[A-Za-z0-9]+)\s*,\s*(?P<source>\[[^\]]+\])$", re.IGNORECASE)


class DebugConsole:
    """Manages launching the debug console window and communication with the debug server via a named pipe."""

    def __init__(self, parent, title, windowPosition, windowSize):
        self.parent = parent
        self.title = title
        self.windowPosition = windowPosition
        self.windowSize = windowSize
        self.pipe = DEBUG_PIPE
        self.frame = None

        # These shared condition variables and buffers are used by the pipe handler.
        self.breakCondition = Condition()
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
        # noinspection PyTypeChecker
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
        wx.CallAfter(self.frame.consolePanel.InitPipe)
        log.info("[DEBUG CONSOLE] Console launched.")

    def shutdown(self):
        """Gracefully shuts down the debug console and disconnects any open pipes."""
        if self.frame:
            wx.CallAfter(self.frame.Close)
        disconnect_pipes()


class ConsoleFrame(wx.Frame):
    def __init__(self, parent, title, window_position, window_size):
        super().__init__(None, title=title, pos=window_position, size=window_size)
        self.parent = parent
        self.pipe = parent.pipe
        self.consolePanel = ConsolePanel(self)
        self.Bind(wx.EVT_CLOSE, self.OnClose)

        self.ID_STOP = wx.NewIdRef()
        self.ID_STEP_INTO = wx.NewIdRef()
        self.ID_STEP_OVER = wx.NewIdRef()
        self.ID_STEP_OUT = wx.NewIdRef()
        self.ID_RUN_UNTIL = wx.NewIdRef()
        self.ID_CONTINUE = wx.NewIdRef()
        self.ID_BACK = wx.NewIdRef()
        self.ID_SEARCH = wx.NewIdRef()

        # Space is handled by DisassemblyListCtrl.OnKeyDown, not here: as an accelerator it
        # fired frame-wide and stole activation from whichever button had focus.
        accels = wx.AcceleratorTable(
            [
                (wx.ACCEL_NORMAL, wx.WXK_F4, self.ID_RUN_UNTIL),
                (wx.ACCEL_NORMAL, wx.WXK_F7, self.ID_STEP_INTO),
                (wx.ACCEL_NORMAL, wx.WXK_F8, self.ID_STEP_OVER),
                (wx.ACCEL_NORMAL, wx.WXK_F9, self.ID_STEP_OUT),
                (wx.ACCEL_NORMAL, wx.WXK_F10, self.ID_CONTINUE),
                (wx.ACCEL_NORMAL, wx.WXK_ESCAPE, self.ID_BACK),
                (wx.ACCEL_CTRL, ord("Q"), self.ID_STOP),
                (wx.ACCEL_CMD, ord("F"), self.ID_SEARCH),
            ]
        )
        self.SetAcceleratorTable(accels)
        self.Bind(wx.EVT_MENU, self.consolePanel.OnRunUntilAccel, id=self.ID_RUN_UNTIL)
        self.Bind(wx.EVT_MENU, lambda evt: self.consolePanel.SendCommand(CMD_STEP_INTO), id=self.ID_STEP_INTO)
        self.Bind(wx.EVT_MENU, lambda evt: self.consolePanel.SendCommand(CMD_STEP_OVER), id=self.ID_STEP_OVER)
        self.Bind(wx.EVT_MENU, lambda evt: self.consolePanel.SendCommand(CMD_STEP_OUT), id=self.ID_STEP_OUT)
        self.Bind(wx.EVT_MENU, lambda evt: self.consolePanel.SendCommand(CMD_CONTINUE), id=self.ID_CONTINUE)
        self.Bind(wx.EVT_MENU, lambda evt: self.consolePanel.ShutdownConsole(), id=self.ID_STOP)
        self.Bind(wx.EVT_MENU, self.OnBack, id=self.ID_BACK)
        self.Bind(wx.EVT_MENU, lambda evt: self.consolePanel.OnDialogSearch(), id=self.ID_SEARCH)

    def OnClose(self, event):
        """Handles window close event gracefully."""
        self.consolePanel.ShutdownConsole()
        self.Destroy()

    def OnBack(self, event):
        focused = wx.Window.FindFocus()
        if not focused:
            return

        ctrl = focused
        while ctrl and not isinstance(ctrl, (DisassemblyListCtrl, MemDumpListCtrl)):
            ctrl = ctrl.GetParent()

        if hasattr(ctrl, "OnBack"):
            ctrl.OnBack(event)


class ConsolePanel(wx.Panel):
    """A wxPython panel that supports multi-threaded debugging with labeled sections, hotkeys, and logging.

    Threading: the page cache (pageBuffers, pendingPages, pageHashes) and the resolution
    maps are touched only from the wx main thread. PipeLoop is the sole reader thread and it
    marshals every message through wx.CallAfter, and CommandPipeHandler talks to DebugConsole
    via breakCondition rather than to this panel. There is deliberately no lock: the previous
    pageLock was taken by the writers but not by DoHotDecode, so it advertised a guarantee it
    did not provide. Anything moved off the main thread has to reintroduce locking at every
    reader as well.
    """

    def __init__(self, parent):
        super().__init__(parent)
        self.parent = parent
        self.pipe = parent.pipe
        self.pipeHandle = None
        self.connected = False
        self.readLock = Lock()
        self.writeQueue = Queue()
        self.slotCount = 512
        self.initMemDump = True
        self.sashesPlaced = False
        self.inspectedTid = None
        self.cip = None
        self.bits = None
        self.pageBuffers: dict[int, bytes] = {}
        # request tag -> page base, for the page loads still outstanding. Correlating by tag
        # means a late response from an earlier break cannot satisfy this break's request.
        self.pendingPages: dict[str, int] = {}
        self.requestId = 0
        self.pageHashes = {}
        self.exports: dict[int, str] = {}
        # Sorted export addresses for nearest-symbol lookup, rebuilt when exports grow.
        self.exportAddrs: list[int] = []
        self.exportModules = []
        self.export = None
        self.resolvedExports: dict[int, dict[int, str]] = {}
        self.resolvedStrings: dict[int, str] = {}
        self.currentExportsModule = None
        self.exportsPage = 0
        self.moduleRanges = []
        self.patchHistory: list[PatchEntry] = []
        self.patchHistoryByAddr: dict[int, list[PatchEntry]] = defaultdict(list)
        self.derefCount = 0
        self.derefPending: set[int] = set()
        self.dumpFilePath = None
        self.assembler = None
        self.firstBreak = True
        self.CMD_PAGE_MAP = None
        self.CMD_PAGE_LOAD = None
        self.CMD_REG_UPDATE = None
        self.CMD_MEM_DUMP = None
        self.CMD_STACK_UPDATE = None
        self.CMD_CONTINUE = None
        self.CMD_SET_BREAKPOINT = None
        self.CMD_DELETE_BREAKPOINT = None
        self.CMD_BREAKPOINT_LIST = None
        self.CMD_THREADS = None
        self.CMD_MODULE_LIST = None
        self.CMD_EXPORTS = None
        self.CMD_MOD_FLAG = None
        self.CMD_SET_CIP = None
        self.CMD_NOP_INSTRUCTION = None
        self.CMD_PATCH_BYTES = None
        self.InitGUI()

    def InitGUI(self):
        # Main Layout
        MAX_BTN_W = 120
        mainSizer = wx.BoxSizer(wx.VERTICAL)
        fontCourier = FONT_CODE

        # The four main views live in splitter panes so their boundaries can be dragged; the
        # panes were fixed sizer proportions before. Controls that call back into this panel
        # are given console=self, because their wx parent is now a pane rather than the panel.
        self.paneSplitter = wx.SplitterWindow(self, style=wx.SP_LIVE_UPDATE | wx.SP_3DSASH)
        self.topSplitter = wx.SplitterWindow(self.paneSplitter, style=wx.SP_LIVE_UPDATE | wx.SP_3DSASH)
        self.bottomSplitter = wx.SplitterWindow(self.paneSplitter, style=wx.SP_LIVE_UPDATE | wx.SP_3DSASH)
        for splitter in (self.paneSplitter, self.topSplitter, self.bottomSplitter):
            splitter.SetMinimumPaneSize(MIN_PANE)

        # Disassembly
        disasmPane = wx.Panel(self.topSplitter)
        consoleSizer = wx.BoxSizer(wx.VERTICAL)
        consoleSizer.Add(wx.StaticText(disasmPane, label="Disassembly Console"), 0, wx.ALL, 5)
        self.disassemblyConsole = DisassemblyListCtrl(disasmPane, console=self)
        self.disassemblyConsole.SetFont(fontCourier)
        consoleSizer.Add(self.disassemblyConsole, 1, wx.EXPAND | wx.ALL, 5)
        disasmPane.SetSizer(consoleSizer)

        # Registers
        regsPane = wx.Panel(self.topSplitter)
        regsSizer = wx.BoxSizer(wx.VERTICAL)
        regsSizer.Add(wx.StaticText(regsPane, label="Registers"), 0, wx.ALL, 5)
        self.threadBanner = wx.StaticText(regsPane, label="")
        self.threadBanner.Hide()
        regsSizer.Add(self.threadBanner, 0, wx.LEFT | wx.RIGHT | wx.BOTTOM, 5)
        self.regsDisplay = RegsTextCtrl(regsPane, style=wx.TE_MULTILINE | wx.TE_READONLY, console=self)
        self.regsDisplay.SetFont(fontCourier)
        regsSizer.Add(self.regsDisplay, 1, wx.EXPAND | wx.ALL, 5)
        regsPane.SetSizer(regsSizer)

        # Memory Dump
        memPane = wx.Panel(self.bottomSplitter)
        memSizer = wx.BoxSizer(wx.VERTICAL)
        memSizer.Add(wx.StaticText(memPane, label="Memory Dump"), 0, wx.ALL, 5)
        self.memDumpDisplay = MemDumpListCtrl(memPane, console=self)
        self.memDumpDisplay.SetFont(fontCourier)
        memSizer.Add(self.memDumpDisplay, 1, wx.EXPAND | wx.ALL, 5)

        # Address input field
        memInput = wx.BoxSizer(wx.HORIZONTAL)
        memInput.Add(wx.StaticText(memPane, label="Memory Dump Address:"), 0, wx.LEFT | wx.ALIGN_CENTER_VERTICAL, 5)
        self.memAddressInput = wx.TextCtrl(memPane, style=wx.TE_PROCESS_ENTER)
        self.memAddressInput.SetFont(fontCourier)
        memInput.Add(self.memAddressInput, 1, wx.EXPAND | wx.ALL, 5)
        self.memAddressInput.Bind(wx.EVT_TEXT_ENTER, self.OnAddressEnter)

        # Dump to File button
        btnDumpToFile = wx.Button(memPane, label="Dump Memory to File")
        btnDumpToFile.Bind(wx.EVT_BUTTON, self.OnDumpToFile)
        memInput.Add(btnDumpToFile, 0, wx.LEFT | wx.ALIGN_CENTER_VERTICAL, 5)
        memSizer.Add(memInput, 0, wx.EXPAND | wx.ALL, 5)
        memPane.SetSizer(memSizer)

        # Stack and Call Stack share the pane: raw stack words answer "what is on the
        # stack", walked frames answer "how did execution get here".
        stackPane = wx.Panel(self.bottomSplitter)
        stackSizer = wx.BoxSizer(wx.VERTICAL)
        self.stackNotebook = wx.Notebook(stackPane)

        rawPage = wx.Panel(self.stackNotebook)
        rawSizer = wx.BoxSizer(wx.VERTICAL)
        self.stackDisplay = StackListCtrl(rawPage, console=self)
        self.stackDisplay.SetFont(fontCourier)
        rawSizer.Add(self.stackDisplay, 1, wx.EXPAND | wx.ALL, 3)
        rawPage.SetSizer(rawSizer)
        self.stackNotebook.AddPage(rawPage, "Stack")

        framePage = wx.Panel(self.stackNotebook)
        frameSizer = wx.BoxSizer(wx.VERTICAL)
        self.callStackDisplay = CallStackListCtrl(framePage, console=self)
        self.callStackDisplay.SetFont(fontCourier)
        frameSizer.Add(self.callStackDisplay, 1, wx.EXPAND | wx.ALL, 3)
        framePage.SetSizer(frameSizer)
        self.stackNotebook.AddPage(framePage, "Call Stack")

        stackSizer.Add(self.stackNotebook, 1, wx.EXPAND | wx.ALL, 5)
        stackPane.SetSizer(stackSizer)

        # Gravity keeps the old proportions when the window itself is resized; the sash
        # positions are set once the panel has a real size, in _InitSashes.
        self.topSplitter.SplitVertically(disasmPane, regsPane)
        self.topSplitter.SetSashGravity(0.6)
        self.bottomSplitter.SplitVertically(memPane, stackPane)
        self.bottomSplitter.SetSashGravity(0.7)
        self.paneSplitter.SplitHorizontally(self.topSplitter, self.bottomSplitter)
        self.paneSplitter.SetSashGravity(0.5)
        mainSizer.Add(self.paneSplitter, 1, wx.EXPAND | wx.ALL, 5)

        # Console box
        consoleSizer = wx.BoxSizer(wx.VERTICAL)
        self.outputConsole = wx.TextCtrl(self, style=wx.TE_MULTILINE | wx.TE_READONLY)
        self.outputConsole.SetFont(fontCourier)
        charH = self.outputConsole.GetCharHeight()
        self.outputConsole.SetMinSize(wx.Size(-1, charH * 7))
        consoleSizer.Add(wx.StaticText(self, label="Console Output"), 0, wx.ALL, 5)
        consoleSizer.Add(self.outputConsole, 1, wx.EXPAND | wx.ALL, 5)

        # Modules List View
        modulesSizer = wx.BoxSizer(wx.VERTICAL)
        modulesSizer.Add(wx.StaticText(self, label="Modules"), 0, wx.ALL, 5)
        self.modulesDisplay = ModulesListCtrl(self)
        self.modulesDisplay.SetFont(fontCourier)
        self.modulesDisplay.SetMinSize(wx.Size(-1, charH * 7))
        modulesSizer.Add(self.modulesDisplay, 1, wx.EXPAND | wx.ALL, 5)

        # Threads List View
        threadsSizer = wx.BoxSizer(wx.VERTICAL)
        threadsSizer.Add(wx.StaticText(self, label="Threads"), 0, wx.ALL, 5)
        self.threadsDisplay = ThreadListCtrl(self)
        self.threadsDisplay.SetFont(fontCourier)
        self.threadsDisplay.SetMinSize(wx.Size(-1, charH * 7))
        threadsSizer.Add(self.threadsDisplay, 1, wx.EXPAND | wx.ALL, 5)

        # Breakpoints List View
        bpsSizer = wx.BoxSizer(wx.VERTICAL)
        bpsSizer.Add(wx.StaticText(self, label="Breakpoints"), 0, wx.ALL, 5)
        self.breakpointsDisplay = BreakpointsListCtrl(self)
        self.breakpointsDisplay.SetFont(fontCourier)
        self.breakpointsDisplay.SetMinSize(wx.Size(-1, charH * 7))
        bpsSizer.Add(self.breakpointsDisplay, 1, wx.EXPAND | wx.ALL, 5)

        miscSizer = wx.BoxSizer(wx.HORIZONTAL)
        miscSizer.Add(consoleSizer, 2, wx.EXPAND | wx.ALL)
        miscSizer.Add(modulesSizer, 4, wx.EXPAND | wx.ALL)
        miscSizer.Add(threadsSizer, 2, wx.EXPAND | wx.ALL)
        miscSizer.Add(bpsSizer, 2, wx.EXPAND | wx.ALL)
        mainSizer.Add(miscSizer, 0, wx.EXPAND)

        # Input box
        inputSizer = wx.BoxSizer(wx.HORIZONTAL)
        inputSizer.Add(wx.StaticText(self, label="Command Input:"), 0, wx.LEFT | wx.ALIGN_CENTER_VERTICAL, 5)
        self.inputBox = wx.TextCtrl(self, style=wx.TE_PROCESS_ENTER)
        self.inputBox.Bind(wx.EVT_TEXT_ENTER, self.OnEnter)
        inputSizer.Add(self.inputBox, 1, wx.EXPAND | wx.ALL, 5)

        # Debugging Controls
        debugButtons = wx.BoxSizer(wx.HORIZONTAL)
        self.runUntilBtn = wx.Button(self, label="Run Until (F4)")
        self.stepIntoBtn = wx.Button(self, label="Step Into (F7)")
        self.stepOverBtn = wx.Button(self, label="Step Over (F8)")
        self.stepOutBtn = wx.Button(self, label="Step Out (F9)")
        self.continueBtn = wx.Button(self, label="Continue (F10)")
        self.runUntilBtn.SetMinSize(wx.Size(MAX_BTN_W, -1))
        self.runUntilBtn.Bind(wx.EVT_BUTTON, self.OnRunUntilAccel)
        debugButtons.Add(self.runUntilBtn, 0, wx.LEFT | wx.BOTTOM, 5)
        for btn, cmd in (
            (self.stepIntoBtn, CMD_STEP_INTO),
            (self.stepOverBtn, CMD_STEP_OVER),
            (self.stepOutBtn, CMD_STEP_OUT),
            (self.continueBtn, CMD_CONTINUE),
        ):
            btn.SetMinSize(wx.Size(MAX_BTN_W, -1))
            btn.Bind(wx.EVT_BUTTON, lambda evt, c=cmd: self.SendCommand(c))
            debugButtons.Add(btn, 0, wx.LEFT | wx.BOTTOM, 5)

        inputSizer.Add(debugButtons, 0, wx.ALIGN_CENTER_VERTICAL | wx.LEFT, 10)

        # Status Bar
        self.statusBar = wx.StaticText(self, label="Status: Disconnected")
        inputSizer.AddStretchSpacer()
        inputSizer.Add(self.statusBar, 0, wx.RIGHT | wx.ALIGN_CENTER_VERTICAL, 5)

        mainSizer.Add(inputSizer, 0, wx.EXPAND)

        self.SetSizer(mainSizer)
        apply_theme(self)
        # SplitterWindow is not a wx.Panel, so apply_theme leaves the sash the native grey.
        for splitter in (self.paneSplitter, self.topSplitter, self.bottomSplitter):
            splitter.SetBackgroundColour(BG_CARD)

        self.Bind(wx.EVT_SIZE, self.OnSize)

    def OnSize(self, event):
        """Place the sashes on the first real size event, then leave them to the user.

        Sash positions cannot be set meaningfully in InitGUI because the panel has no size
        yet, and re-applying them on every resize would fight whatever the user has dragged.
        """
        event.Skip()
        if self.sashesPlaced:
            return

        # Each sash is a fraction of its own splitter, not of the panel: the misc row and the
        # command row sit below paneSplitter, so the panel is taller than it is.
        width, height = self.paneSplitter.GetClientSize()
        if width <= MIN_PANE * 2 or height <= MIN_PANE * 2:
            return

        self.sashesPlaced = True
        self.paneSplitter.SetSashPosition(int(height * 0.5))
        self.topSplitter.SetSashPosition(int(width * 0.6))
        self.bottomSplitter.SetSashPosition(int(width * 0.7))

    def IsAddressKnown(self, addr: int) -> bool:
        pageMap = getattr(self.disassemblyConsole, "pageMap", None)
        if not pageMap:
            return False

        return FindRegion(pageMap, addr) is not None

    def PromptBreakpoint(self, address=""):
        """Ask for breakpoint details and set it. Shared by every entry point."""
        if isinstance(address, int):
            address = f"{address:#x}"

        dlg = BreakpointDialog(self, address or "")
        try:
            if dlg.ShowModal() != wx.ID_OK:
                return

            values = dlg.GetValues()
        finally:
            dlg.Destroy()

        if values is None:
            return

        slot, bpType, size, addr = values
        self.SendCommand(CMD_SET_BREAKPOINT, f"{slot}|{addr:#X}|{bpType}|{size}")

    def OnRunUntilAccel(self, event):
        row = self.disassemblyConsole.GetNextItem(-1, wx.LIST_NEXT_ALL, wx.LIST_STATE_SELECTED)
        if row == -1:
            row = self.disassemblyConsole.GetCipRow(self.cip)

        if row == -1:
            wx.MessageBox("No valid address to Run Until.", "Error", wx.OK | wx.ICON_ERROR)
            return

        self.disassemblyConsole.OnRunUntil(row)

    def OnAddressEnter(self, event):
        self.memAddr = self.memAddressInput.GetValue().strip()
        if self.memAddr:
            self.SendCommand(CMD_MEM_DUMP, self.memAddr, tag=self.NextTag(TAG_DUMP))

        event.Skip()

    def OnDumpToFile(self, event):
        addrStr = wx.GetTextFromUser("Enter starting address (hex or decimal):", "Dump to File")
        if not addrStr:
            return

        try:
            addr = int(addrStr, 0)
        except ValueError:
            wx.MessageBox("Invalid address format.", "Error", wx.OK | wx.ICON_ERROR)
            return

        sizeStr = wx.GetTextFromUser("Enter dump size in bytes (hex or decimal):", "Dump to File")
        if not sizeStr:
            return

        try:
            size = int(sizeStr, 0)
        except ValueError:
            wx.MessageBox("Invalid size format.", "Error", wx.OK | wx.ICON_ERROR)
            return

        formats = ["Binary file (*.bin)", "Text file (*.txt)"]
        with wx.SingleChoiceDialog(self, "Select output format:", "Dump to File", formats) as choiceDialog:
            if choiceDialog.ShowModal() != wx.ID_OK:
                return
            formatChoice = choiceDialog.GetStringSelection()

        wildcard = "Text files (*.txt)|*.txt"
        if "Binary" in formatChoice:
            wildcard = "Binary files (*.bin)|*.bin"

        with wx.FileDialog(
            self,
            "Save Memory Dump",
            wildcard=wildcard,
            style=wx.FD_SAVE | wx.FD_OVERWRITE_PROMPT,
        ) as fileDialog:
            if fileDialog.ShowModal() == wx.ID_CANCEL:
                return

            self.dumpFilePath = fileDialog.GetPath()

        self.SendCommand(CMD_MEM_DUMP, f"{addr:#x}|{size:#x}", tag=self.NextTag(TAG_FILE))

    def WriteMemToFile(self, data):
        try:
            if self.dumpFilePath.endswith(".bin"):
                with open(self.dumpFilePath, "wb") as f:
                    f.write(bytes.fromhex(data))
            else:
                with open(self.dumpFilePath, "w", encoding="utf-8") as f:
                    f.write(data)

            wx.MessageBox(f"Memory dumped successfully to:\n{self.dumpFilePath}", "Success", wx.OK | wx.ICON_INFORMATION)
        except Exception as e:
            wx.MessageBox(f"Failed to dump memory: {e}", "Error", wx.OK | wx.ICON_ERROR)


    def AppendConsole(self, text: str):
        """Appends text to the output console."""
        if not isinstance(text, str):
            return

        self.outputConsole.AppendText(text + "\n")

    def UpdateRegs(self, text):
        """Update registers display."""
        self.regsDisplay.Clear()
        self.regsDisplay.SetValue(text)
        regsText = self.regsDisplay.GetValue()
        m = re.search(r"\b([ER]IP):\s*([0-9A-Fa-f]+)", regsText)
        # Never drop a known-good CIP: this runs on every break, and nulling it here blanks
        # the disassembly highlight and takes GetCipRow/DoHotDecode down with it.
        if m:
            self.cip = int(m.group(2), 16)
        else:
            log.warning("[DEBUG CONSOLE] No instruction pointer in register payload; keeping the previous CIP")
        if not self.bits:
            self.bits = 64 if "RAX" in regsText else 32
            self.assembler = Assembler(self.bits)

    def UpdateStack(self, data):
        """Update stack display."""
        self.stackDisplay.UpdateData(data)

    def UpdateMemDump(self, data):
        """Update memory dump display."""
        self.memDumpDisplay.UpdateData(data)

    def UpdateThreads(self, data):
        """Update memory dump display."""
        self.threadsDisplay.UpdateData(data)

    def UpdateBreakpoints(self, data):
        """Update breakpoints display."""
        self.breakpointsDisplay.UpdateData(data)

    def UpdateModules(self, data):
        """Update modules display."""
        self.modulesDisplay.UpdateData(data)

    def UpdateStatus(self, status):
        self.statusBar.SetLabel(status)

    def InitPipe(self):
        Thread(target=self.WriteLoop, daemon=True).start()
        Thread(target=self.PipeLoop, daemon=True).start()

    def PipeLoop(self):
        try:
            self.pipeHandle = win32file.CreateFile(
                self.pipe,
                win32file.GENERIC_READ | win32file.GENERIC_WRITE,
                0,
                None,
                win32file.OPEN_EXISTING,
                win32file.FILE_FLAG_OVERLAPPED,
                None,
            )
            log.info("[DEBUG CONSOLE] Console connected to named pipe.")
        except Exception as e:
            log.error("[DEBUG CONSOLE] Console failed to connect to named pipe: %s", e)

        self.SendInit()
        while True:
            msg = self.ReadResponse()
            if msg is None:
                break

            if not msg:
                continue

            wx.CallAfter(self.ProcessServerOutput, msg)

        win32file.CloseHandle(self.pipeHandle)
        self.pipeHandle = None
        log.info("[DEBUG CONSOLE] Reader thread exiting, pipe closed.")

    def SendInit(self):
        if not self.pipeHandle:
            return

        log.info("[DEBUG CONSOLE] Sending init command...")
        self.SendCommand("init")

    def ReadResponse(self):
        """Reads a full response from the pipe in a thread-safe manner."""
        with self.readLock:
            if not self.pipeHandle:
                return None

            try:
                _, data = win32file.ReadFile(self.pipeHandle, BUFFER_SIZE)
                response = data.decode("utf-8").strip()
                return response
            except Exception as e:
                log.error("[DEBUG CONSOLE] Reading response: %s", e)
                return None

    def NextTag(self, purpose: str) -> str:
        """Allocate a request tag; the id disambiguates two requests of the same purpose."""
        self.requestId += 1
        return f"{self.requestId}:{purpose}"

    def SendCommand(self, command, data="", tag=None):
        if command.lower() != "init" and (not self.connected or not self.pipeHandle):
            log.error("[DEBUG CONSOLE] Cannot send command: Not connected to pipe")
            return

        if tag:
            data = f"{tag}|{data}"

        fullCommand = f"{DBGCMD}:{command.upper()}:{data}".encode() + b"\n"
        self.writeQueue.put(fullCommand)

    def WriteLoop(self):
        """Serialise pipe writes.

        A thread per command meant RefreshViewState's five commands raced each other onto the
        same handle, so the debug server received them in an arbitrary order.
        """
        while True:
            buffer = self.writeQueue.get()
            if buffer is None:
                return

            self.BackgroundWrite(buffer, 5000)

    def BackgroundWrite(self, buffer, timeout=win32event.INFINITE):
        if not self.pipeHandle:
            log.error("[DEBUG CONSOLE] Dropping command: pipe is closed")
            return

        overlapped = pywintypes.OVERLAPPED()
        overlapped.hEvent = win32event.CreateEvent(None, 0, 0, None)
        try:
            win32file.WriteFile(self.pipeHandle, buffer, overlapped)
            rc = win32event.WaitForSingleObject(overlapped.hEvent, timeout)
            if rc != win32event.WAIT_OBJECT_0:
                log.error("[DEBUG CONSOLE] Write timed out or failed: %s", rc)
            else:
                win32file.GetOverlappedResult(self.pipeHandle, overlapped, True)
        except pywintypes.error as e:
            log.error("[DEBUG CONSOLE] Pipe write error: %s", e)
        finally:
            if overlapped.hEvent:
                win32file.CloseHandle(overlapped.hEvent)

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
            self.SendCommand(CMD_CONTINUE)
            self.ShutdownConsole()
        elif cmd == "clear":
            self.outputConsole.Clear()
        elif cmd in ("",):
            pass
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
        self.writeQueue.put(None)
        if self.pipeHandle:
            try:
                win32file.CloseHandle(self.pipeHandle)
            except Exception as e:
                log.error("[DEBUG CONSOLE] Error closing pipe handle: %s", e)
            finally:
                self.pipeHandle = None
                log.info("[DEBUG CONSOLE] Pipe handle closed")

    def RefreshViewState(self):
        if self.inspectedTid is not None:
            self.inspectedTid = None
            self.ShowThreadBanner(None)

        self.SendCommand(CMD_REG_UPDATE)
        if self.initMemDump:
            self.SendCommand(CMD_MEM_DUMP, tag=self.NextTag(TAG_DUMP))
            self.initMemDump = False
        else:
            # Re-dump whatever region is on screen. This used to overwrite the address box
            # and fire a synthetic EVT_TEXT_ENTER, which blanked the field on every break.
            addr = self.memDumpDisplay.GetFirstHexAddress()
            if addr is not None:
                self.SendCommand(CMD_MEM_DUMP, addr, tag=self.NextTag(TAG_DUMP))

        self.SendCommand(CMD_STACK_UPDATE)
        self.SendCommand(CMD_CALL_STACK)
        self.SendCommand(CMD_THREADS)
        self.SendCommand(CMD_BREAKPOINT_LIST)

    def RefreshPageMap(self):
        self.SendCommand(CMD_PAGE_MAP)

    def RefreshModuleList(self):
        self.SendCommand(CMD_MODULE_LIST)

    def DispatchCommand(self, command, payload):
        """Dispatch commands to their respective handlers."""
        handlers = {
            CMD_PAGE_MAP: self.HandlePageMap,
            CMD_PAGE_LOAD: self.HandlePageLoad,
            CMD_REG_UPDATE: self.HandleRegUpdate,
            CMD_MEM_DUMP: self.HandleMemDump,
            CMD_STACK_UPDATE: self.HandleStackUpdate,
            CMD_CALL_STACK: self.HandleCallStack,
            CMD_THREAD_INSPECT: self.HandleThreadInspect,
            CMD_SET_BREAKPOINT: self.HandleSetBreakpoint,
            CMD_DELETE_BREAKPOINT: self.HandleDeleteBreakpoint,
            CMD_BREAKPOINT_LIST: self.HandleBreakpointsList,
            CMD_THREADS: self.HandleThreads,
            CMD_MODULE_LIST: self.HandleModules,
            CMD_EXPORTS: self.HandleExports,
            CMD_SET_REGISTER: self.HandleSetRegister,
            CMD_MOD_FLAG: self.HandleModFlag,
            CMD_NOP_INSTRUCTION: self.HandleNopInstruction,
            CMD_PATCH_BYTES: self.HandlePatchBytes,
        }

        if command in CMD_CONSOLE:
            self.HandleConsoleOutput(payload)
            return

        if command in CMD_EXECUTION:
            self.HandleExecution(payload)
            return

        handler = handlers.get(command)
        if handler:
            handler(payload)
        else:
            log.warning("[DEBUG CONSOLE] Unknown command '%s' received", command)

    def RequestPage(self, pageBase: int):
        tag = self.NextTag(TAG_PAGE)
        self.pendingPages[tag] = pageBase
        self.SendCommand(CMD_PAGE_LOAD, hex(pageBase), tag=tag)

    def JumpTo(self, address: int):
        """Use pageMap to find page."""
        self.cip = address
        if not self.AddressInModules(address):
            self.RefreshModuleList()

        region = self.disassemblyConsole.FindPage(address)
        if region is None:
            self.RefreshPageMap()
            return

        pages = SelectWindowPages(self.disassemblyConsole.pageMap, self.cip, PAGE_SIZE, CHUNK_SIZE)
        if not pages:
            log.error("[DEBUG CONSOLE] No valid pages found for address %#x", address)
            return

        # Landing outside every buffered page means a jump to a different region, so nothing
        # held is worth keeping. Within a region the cache is retained: re-reading the whole
        # 36 KB window took ~9 pipe round-trips to advance one instruction.
        regionChange = not CoversAddress(self.pageBuffers, self.cip, PAGE_SIZE)
        hot = set(HotPages(self.cip, PAGE_SIZE)) & set(pages)
        if regionChange:
            self.pageBuffers.clear()

        for page in DistantPages(list(self.pageBuffers), self.cip, PAGE_SIZE, KEEP_PAGES):
            del self.pageBuffers[page]
            self.pageHashes.pop(page, None)

        # Drop the hot pages so a stale copy can never be decoded if the re-read fails.
        for page in hot:
            self.pageBuffers.pop(page, None)

        # HotPages always contributes CIP's own page, so this is never empty and a page
        # load response is always coming to trigger the decode.
        for page in sorted(page for page in pages if page not in self.pageBuffers):
            self.RequestPage(page)

        self.RefreshViewState()

    def DoHotDecode(self):
        """Decode the contiguous buffered span from CIP forward and update the view."""
        if self.cip is None:
            log.warning("[DEBUG CONSOLE] Hot decode skipped: no current instruction pointer")
            return

        spanData = ContiguousSpan(self.pageBuffers, self.cip, PAGE_SIZE, CHUNK_SIZE)
        if not spanData:
            log.warning("[DEBUG CONSOLE] No contiguous page data at CIP %#x; refreshing page map", self.cip)
            self.RefreshPageMap()
            return

        cache = self.disassemblyConsole.decodeCache
        # pageHashes still holds the hashes from before this break's re-read (HandlePageLoad
        # records the new ones after this returns), so this asks whether the code changed.
        rewritten = any(
            PageChanged(self.pageHashes, page, self.pageBuffers.get(page))
            for page in PagesOfSpan(self.cip, len(spanData), PAGE_SIZE)
        )
        # A plain step usually decodes the same instructions with the split moved along by
        # one, so when the bytes are untouched and CIP is already a known boundary there is
        # nothing to decode and nothing to re-render - just move the highlight.
        if not rewritten and self.disassemblyConsole.GetCipRow() != -1:
            self.disassemblyConsole.HighlightCip(self.disassemblyConsole.GetCipRow())
            return

        # Keep anywhere the user can navigate back to, or has marked, regardless of distance.
        pinned = set(self.disassemblyConsole.backHistory)
        pinned |= self.disassemblyConsole.bpAddrs
        pinned |= set(self.patchHistoryByAddr)
        prefix = BoundInstructions(
            [ins for ins in cache if ins.address < self.cip], self.cip, KEEP_PAGES * PAGE_SIZE, pinned
        )
        mode = Decode64Bits if self.bits == 64 else Decode32Bits
        insts: list[DecodedInstruction] = []
        for address, size, text, hexBytes in Decode(self.cip, spanData, mode):
            patchText = self.PatchDisasmText(address, text)
            insts.append(DecodedInstruction(address, hexBytes, patchText))

        # SetInstructions owns decodeCache: assigning it here first would make the incremental
        # diff see the new stream as already rendered and skip every row.
        self.disassemblyConsole.SetInstructions(prefix + insts)

    def UpdateDisassemblyView(self):
        insts: list[DecodedInstruction] = []
        cache = getattr(self.disassemblyConsole, "decodeCache", [])
        for inst in cache:
            patchText = self.PatchDisasmText(inst.address, inst.text)
            insts.append(DecodedInstruction(inst.address, inst.bytes, patchText))

        self.disassemblyConsole.SetInstructions(insts)
        self.RefreshViewState()

    def DeReferenceCalls(self):
        cache = getattr(self.disassemblyConsole, "decodeCache", [])
        for inst in cache:
            if "call" not in inst.text.lower():
                continue

            try:
                ripBase = inst.address + len(inst.bytes) // 2
                targetAddr = self.disassemblyConsole.ParseOperandAddress(inst.text, ripBase)
            except Exception:
                continue

            if targetAddr is None:
                continue

            if targetAddr not in self.derefPending:
                self.derefPending.add(targetAddr)
                self.derefCount += 1

            self.resolvedExports[inst.address] = {targetAddr: ""}

            wx.CallLater(1, self.ResolveRef, targetAddr)

        # Nothing to resolve means no response will arrive to re-enable the menu item.
        if not self.derefCount:
            self.disassemblyConsole.resolveAllRefsStatus = True

    def GetCip(self, data):
        m = re.search(r"0x[0-9a-fA-F]+", data)
        if m:
            cip = int(m.group(0), 16)
            self.cip = cip

    def ResolveRef(self, addr):
        addrStr = addr
        if isinstance(addr, int):
            addrStr = f"{addr:#x}"

        if addrStr and IsValidHexAddress(addrStr):
            size = 4 if self.bits == 32 else 8
            self.SendCommand(CMD_MEM_DUMP, f"{addrStr}|{hex(size)}", tag=self.NextTag(TAG_DEREF))

    def ResolveString(self, addr: int):
        addrStr = addr
        if isinstance(addr, int):
            addrStr = f"{addr:#x}"

        if addrStr and IsValidHexAddress(addrStr):
            self.SendCommand(CMD_MEM_DUMP, f"{addrStr}|{hex(MAX_LEN)}", tag=self.NextTag(TAG_STR))

    @staticmethod
    def ProcessStringDump(raw: bytes, secondPass: bool = False) -> str:
        s = None
        if not secondPass:
            pos = raw.find(b"\x00")
            if pos != -1:
                with suppress(UnicodeDecodeError, LookupError):
                    s = raw[:pos].decode("utf-8")
        else:
            term = raw.find(b"\x00\x00")
            if term != -1:
                with suppress(UnicodeDecodeError, LookupError):
                    s = raw[:term].decode("utf-16le")

        return s

    def PatchDisasmText(self, addr: int, disasmText: str) -> str:
        export = None
        exportMap = self.resolvedExports.get(addr)
        if exportMap:
            export = next(iter(exportMap.values()), None)

        name = export or self.exports.get(addr) or self.resolvedStrings.get(addr)
        if name:
            m = JMP_CALL_ADDR_RX.search(disasmText)
            if m:
                mnemonic = m.group("mnemonic")
                dest = None
                raw = m.group("operand")
            else:
                m2 = LEA_MOV_ADDR_RX.search(disasmText)
                if not m2:
                    return disasmText

                mnemonic = m2.group("mnemonic")
                dest = m2.group("dest")
                raw = m2.group("source")

            return f"{mnemonic} {dest}, {name}" if dest else f"{mnemonic} {name}"

        return disasmText

    def GetAllExports(self, modules: list[tuple[str, str, str, str]]):
        self.exportModules = list(modules)
        self.LoadNextModuleExports()

    def LoadNextModuleExports(self):
        if not self.exportModules:
            # log.info("[DEBUG CONSOLE] Finished loading all exports.")
            return

        _, _, modName, _ = self.exportModules.pop(0)
        self.exportsPage = 0
        self.currentExportsModule = modName
        self.RequestNextExportsPage()

    def RequestNextExportsPage(self):
        data = f"{self.currentExportsModule}|{self.exportsPage}"
        self.SendCommand(CMD_EXPORTS, data)

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

    def BuildModuleRanges(self, modules: list[tuple[str, str, str, str]]) -> bool:
        """Rebuild the sorted module ranges, returning whether the set changed.

        This used to append without clearing, so every module list refresh duplicated every
        entry and unloaded modules were never dropped - AddressInModules kept reporting freed
        ranges as live.
        """
        ranges = []
        for modBase, modSize, modName, modPath in modules:
            start = int(modBase, 16)
            end = start + int(modSize, 16)
            ranges.append((start, end, modName))

        ranges.sort()
        changed = ranges != self.moduleRanges
        self.moduleRanges = ranges
        return changed

    def AddressInModules(self, cip: int) -> bool:
        idx = bisect.bisect_right(self.moduleRanges, (cip,))
        if idx:
            start, end, modName = self.moduleRanges[idx - 1]
            if start <= cip < end:
                return True

        return False

    def OnDialogSearch(self):
        dlg = getattr(self.modulesDisplay, "dlg", None)
        if dlg and dlg.IsShown():
            dlg.OnSearch()

    def HandleConnection(self, payload):
        """Handle initial connection logic."""
        self.connected = True
        self.UpdateStatus("Status: Connected")
        if not self.parent.IsShown():
            self.parent.Show()
            self.parent.Layout()

        self.AppendConsole(payload)
        self.SendCommand(CMD_REG_UPDATE)
        self.RefreshModuleList()

    def HandleSetBreakpoint(self, payload):
        self.AppendConsole(payload)
        if "Failed" in payload:
            return

        m = re.search(r"0x[0-9a-fA-F]+", payload)
        if m:
            addr = int(m.group(0), 16)
            self.disassemblyConsole.SetBpBackground(addr)
            self.SendCommand(CMD_BREAKPOINT_LIST)

    def HandleDeleteBreakpoint(self, payload):
        self.AppendConsole(payload)
        if "Failed" in payload:
            return

        m = re.search(r"0x[0-9a-fA-F]+", payload)
        if m:
            addr = int(m.group(0), 16)
            self.disassemblyConsole.ClearBpBackground(addr)
            self.SendCommand(CMD_BREAKPOINT_LIST)

    def HandleBreakpointsList(self, payload):
        if payload.startswith("Failed"):
            return

        bps: list[tuple[str, str]] = []
        if "No" in payload:
            self.UpdateBreakpoints("")
            return

        for bp in payload.split("|"):
            # str.split never raises, so the old `except ValueError` here was dead and a
            # short entry reached UpdateData, where unpacking it killed the whole handler.
            # Entries are "dr,address,type,size"; older monitors sent only the first two.
            parts = [part.strip() for part in bp.split(",")]
            if len(parts) == 2:
                parts += ["x", "1"]

            if len(parts) != 4:
                log.warning("[DEBUG CONSOLE] Skipping malformed breakpoint entry: %r", bp)
                continue

            bps.append(tuple(parts))
        if bps:
            self.UpdateBreakpoints(bps)

    def HandleThreads(self, payload):
        if payload.startswith("Failed"):
            log.warning("[DEBUG CONSOLE] Threads: %s", payload)
            return

        curThread = None
        tmpThreads: list[tuple[str, str]] = []
        threads: list[tuple[str, str]] = []
        for line in payload.splitlines():
            parts = [p.strip() for p in line.split("|")]
            if len(parts) != 3:
                continue

            entry = (parts[1], parts[2])
            if parts[0] == "+":
                curThread = entry
            else:
                tmpThreads.append(entry)

        if curThread:
            threads.append(curThread)
        threads.extend(tmpThreads)
        self.UpdateThreads(threads)

    def HandleModules(self, payload):
        if payload.startswith("Failed"):
            log.warning("[DEBUG CONSOLE] Modules: %s", payload)
            return

        modules: list[tuple[str, str, str, str]] = []
        if "|" not in payload:
            return

        for mod in payload.split("|"):
            try:
                modBaseAddr, modSize, modName, modPath = mod.split(",")
                modules.append((modBaseAddr, modSize, modName, modPath))
            except ValueError:
                continue

        if modules:
            # A load or unload changes what is mapped, so retained pages can no longer be
            # trusted; drop them and let the next JumpTo re-read the window.
            if self.BuildModuleRanges(modules):
                self.pageBuffers.clear()

            self.GetAllExports(modules)
            self.UpdateModules(modules)

        if self.AddressInModules(self.cip) or self.firstBreak:
            self.firstBreak = False
            self.JumpTo(self.cip)

    def HandleExports(self, payload):
        if payload.startswith("Failed"):
            log.warning("[DEBUG CONSOLE] Exports: %s", payload)
            return

        if "||" not in payload:
            return

        try:
            modName, *data, status = payload.split("||", 2)
        except ValueError:
            wx.CallAfter(self.LoadNextModuleExports)
            return

        if data[0] and modName:
            exports = data[0].split("|")
            for entry in exports:
                if not entry:
                    continue

                try:
                    absAddr, symName = entry.split(",", 1)
                    self.exports[int(absAddr)] = f"{modName}!{symName}"
                except ValueError:
                    continue

        if status == "MORE":
            self.exportsPage += 1
            wx.CallAfter(self.RequestNextExportsPage)
        else:
            wx.CallAfter(self.LoadNextModuleExports)

    def HandlePageMap(self, payload):
        self.disassemblyConsole.LoadPageMap(payload)
        self.pageBuffers.clear()
        self.pendingPages.clear()
        self.pageHashes.clear()

        cip = self.cip
        if not self.IsAddressKnown(cip):
            log.debug(f"[DEBUG] CIP 0x{cip:X} is not present in the new PageMap; waiting for next execution update.")
            return

        pagesToRequest = SelectWindowPages(self.disassemblyConsole.pageMap, cip, PAGE_SIZE, CHUNK_SIZE)
        if not pagesToRequest:
            self.JumpTo(cip)
            return

        for pageBase in sorted(pagesToRequest):
            self.RequestPage(pageBase)

        self.RefreshViewState()

    def HandlePageLoad(self, payload):
        if "Failed" in payload:
            log.debug(f"[DEBUG] PageLoad reported failure: {payload}")
            self.RefreshPageMap()
            self.RefreshModuleList()
            return

        try:
            requestAddr, tag, pageData = payload.split("|", 2)
            pageBase = int(requestAddr, 16)
        except ValueError as e:
            log.error("[DEBUG CONSOLE] Page load payload invalid: %s (%s)", payload, str(e))
            log.error("[DEBUG CONSOLE] %s", STALE_MONITOR_MSG)
            # This branch cannot name the page, so let the page map round-trip clear the set
            # rather than leaving a request outstanding and the view frozen.
            self.RefreshPageMap()
            return

        # A tag from an earlier break is not an answer to the current request: dropping it
        # here is what keeps a stale page out of the buffers when stepping quickly.
        if self.pendingPages.pop(tag, None) is None:
            log.debug("[DEBUG] Ignoring unsolicited or stale page response for 0x%X (tag %s)", pageBase, tag)
            return

        if pageData in ("UNREADABLE", "NODATA"):
            log.debug(f"[DEBUG] PageLoad returned {pageData} for page 0x{pageBase:X}. Refreshing PageMap + ModuleList.")
            self.RefreshPageMap()
            self.RefreshModuleList()
            return

        validPages = False
        if pageData:
            with suppress(ValueError):
                pageData = bytes.fromhex(pageData)
                validPages = True

        if validPages:
            region = self.disassemblyConsole.FindPage(pageBase)
            if not region:
                # The map cannot place this page, so its true extent is unknown and trimming
                # is impossible; buffering it would let a decode run past the region.
                log.debug("[DEBUG] Page 0x%X is not in the page map; discarding and refreshing.", pageBase)
                self.RefreshPageMap()
                return

            expected = min(PAGE_SIZE, region[1] - (pageBase - region[0]))
            if len(pageData) > expected:
                pageData = pageData[:expected]

            self.pageBuffers[pageBase] = pageData

        if not self.pendingPages:
            # DoHotDecode compares against the hashes from before this read to decide whether
            # the code was rewritten, so it has to run before they are replaced.
            self.DoHotDecode()
            for page, data in self.pageBuffers.items():
                self.pageHashes[page] = PageHash(data)

    def HandleRegUpdate(self, payload):
        if payload.startswith("Failed"):
            log.warning("[DEBUG CONSOLE] Registers: %s", payload)
            return

        self.UpdateRegs(payload)

    def HandleModFlag(self, payload):
        if payload.startswith("Failed"):
            log.warning("[DEBUG CONSOLE] Flag: %s", payload)
            return

        self.UpdateRegs(payload)

    def HandleSetRegister(self, payload):
        if payload.startswith("Failed"):
            log.warning("[DEBUG CONSOLE] Set register: %s", payload)
            return

        self.UpdateRegs(payload)

    def GetExport(self, payload):
        try:
            buffer = bytes.fromhex(payload)
            if len(buffer) == 4:
                unpackFmt = "<I"
            elif len(buffer) == 8:
                unpackFmt = "<Q"
            else:
                return

            leaddr = struct.unpack(unpackFmt, buffer)[0]
            return self.exports.get(leaddr, "")
        except ValueError:
            return None

    def HandleMemDump(self, payload):
        if payload.startswith("Failed"):
            if hasattr(self, "derefPending"):
                m = re.search(r"0x[0-9a-fA-F]+", payload)
                if m:
                    failedAddr = int(m.group(0), 16)
                    if failedAddr in self.derefPending:
                        self.derefPending.remove(failedAddr)
                        if self.derefCount > 0:
                            self.derefCount -= 1

            log.debug("[DEBUG] MemDump fault detected, refreshing PageMap + ModuleList")
            self.RefreshPageMap()
            self.RefreshModuleList()
            return

        # The response carries back the tag of the request that caused it, so the purpose is
        # known rather than inferred from len(data). Under the old scheme a "Dump Memory to
        # File" of 4, 8, 256 or 512 bytes was indistinguishable from a pointer or string read.
        try:
            requestAddr, tag, data = payload.split("|", 2)
            addr = int(requestAddr, 16)
        except ValueError:
            log.error("[DEBUG CONSOLE] Memory dump payload invalid: %s", payload)
            log.error("[DEBUG CONSOLE] %s", STALE_MONITOR_MSG)
            self.AppendConsole(STALE_MONITOR_MSG)
            return

        purpose = tag.split(":", 1)[-1]

        if data in ("UNREADABLE", "NODATA"):
            log.debug(f"[DEBUG] MemDump returned {data} for 0x{addr:X}. Refreshing memory map.")
            if purpose == TAG_FILE:
                self.AppendConsole(f"Memory dump to file failed: {addr:#x} is {data}")

            self.RefreshPageMap()
            self.RefreshModuleList()
            return

        if purpose == TAG_FILE:
            if self.dumpFilePath:
                self.WriteMemToFile(data)

            return

        if purpose == TAG_DEREF:
            export = self.GetExport(data)
            instAddrs = [instAddr for instAddr, exportMap in self.resolvedExports.items() if addr in exportMap]
            for instAddr in instAddrs:
                if export:
                    self.resolvedExports[instAddr][addr] = export
                else:
                    del self.resolvedExports[instAddr]

            if addr in self.derefPending:
                self.derefPending.remove(addr)
                if self.derefCount > 0:
                    self.derefCount -= 1

            if export:
                self.AppendConsole(export)

            # Only a bulk resolve (which clears resolveAllRefsStatus) should rebuild the whole
            # view. Without this gate every single-pointer resolve ran a full rebuild plus a
            # RefreshViewState, and printed a bogus "Completed resolving calls."
            if not self.disassemblyConsole.resolveAllRefsStatus and self.derefCount == 0:
                self.AppendConsole("Completed resolving calls.")
                self.UpdateDisassemblyView()
                self.disassemblyConsole.resolveAllRefsStatus = True

            return

        if purpose == TAG_STR:
            raw = b""
            with suppress(ValueError):
                raw = bytes.fromhex(data)

            s = self.ProcessStringDump(raw, secondPass=False)
            if not s:
                self.SendCommand(CMD_MEM_DUMP, f"{addr:#x}|{hex(MAX_LEN * 2)}", tag=self.NextTag(TAG_STRW))
                return

            self.AppendConsole(s)
            self.resolvedStrings[addr] = s

            return

        if purpose == TAG_STRW:
            raw = b""
            with suppress(ValueError):
                raw = bytes.fromhex(data)

            s = self.ProcessStringDump(raw, secondPass=True)
            if s:
                self.AppendConsole(s)
                self.resolvedStrings[addr] = s

            # A raw hex blob from a string lookup, not the formatted dump the panel parses.
            return

        if purpose != TAG_DUMP:
            log.warning("[DEBUG CONSOLE] Unknown memory dump purpose %r for %#x", purpose, addr)
            return

        self.UpdateMemDump(data)

    def DecodeCallSite(self, returnAddr: int, hexBytes: str) -> str:
        """Find the CALL that ends exactly where a frame returns to.

        capemon sends the bytes preceding the return address so this costs no extra round
        trip. Decoding backwards is ambiguous, so every start offset is tried and only an
        instruction that ends precisely at the return address is accepted.
        """
        try:
            data = bytes.fromhex(hexBytes)
        except ValueError:
            return ""

        if not data:
            return ""

        mode = Decode64Bits if self.bits == 64 else Decode32Bits
        base = returnAddr - len(data)
        for offset in range(len(data)):
            decoded = Decode(base + offset, data[offset:], mode)
            if not decoded:
                continue

            address, size, text, _ = decoded[0]
            if address + size == returnAddr and text.lower().startswith("call"):
                return text

        return ""

    def ParseFrames(self, payload: str):
        """Turn 'index,returnAddress,framePointer,callBytes' entries into display rows."""
        frames = []
        for entry in payload.split("|"):
            parts = [part.strip() for part in entry.split(",")]
            if len(parts) != 4:
                log.warning("[DEBUG CONSOLE] Skipping malformed call stack frame: %r", entry)
                continue

            index, returnAddr, framePtr, callBytes = parts
            try:
                callSite = self.DecodeCallSite(int(returnAddr, 16), callBytes)
            except ValueError:
                callSite = ""

            frames.append((index, returnAddr, framePtr, callSite))

        return frames

    def HandleCallStack(self, payload):
        if payload.startswith("Failed"):
            log.warning("[DEBUG CONSOLE] Call stack: %s", payload)
            return

        self.callStackDisplay.UpdateData(self.ParseFrames(payload))

    def InspectThread(self, tid: str):
        """Snapshot another thread. Stepping still drives the thread that broke."""
        self.SendCommand(CMD_THREAD_INSPECT, str(tid))

    def ReturnToHaltedThread(self):
        """Drop the inspection view and repopulate from the thread that is actually halted."""
        if self.inspectedTid is None:
            return

        self.inspectedTid = None
        self.ShowThreadBanner(None)
        self.RefreshViewState()

    def ShowThreadBanner(self, tid):
        """Make it unmissable that the panes are not showing the halted thread."""
        if tid is None:
            self.threadBanner.SetLabel("")
            self.threadBanner.Hide()
        else:
            self.threadBanner.SetLabel(f"Viewing thread {tid} - not the halted thread. Double-click the top thread to return.")
            self.threadBanner.SetForegroundColour(ACCENT_ORANGE)
            self.threadBanner.Show()

        self.threadBanner.GetParent().Layout()

    def HandleThreadInspect(self, payload):
        if payload.startswith("Failed"):
            log.warning("[DEBUG CONSOLE] Thread inspect: %s", payload)
            self.AppendConsole(payload)
            return

        sections = {}
        current = None
        for line in payload.splitlines():
            stripped = line.strip()
            if stripped.startswith("[") and stripped.endswith("]"):
                current = stripped[1:-1]
                sections[current] = []
            elif current is not None:
                sections[current].append(line)

        body = {name: "\n".join(lines).strip() for name, lines in sections.items()}
        tid = body.get("TID", "").strip()
        if not tid:
            log.warning("[DEBUG CONSOLE] Thread inspect payload has no TID: %r", payload[:80])
            return

        self.inspectedTid = tid
        # Deliberately not UpdateRegs: that parses RIP into self.cip, and this is another
        # thread's instruction pointer. The disassembly must keep tracking the halted thread.
        self.regsDisplay.SetValue(body.get("REGS", ""))
        if body.get("STACK"):
            self.stackDisplay.UpdateData(body["STACK"])

        self.callStackDisplay.UpdateData(self.ParseFrames(body.get("FRAMES", "")))
        self.ShowThreadBanner(tid)

    def NearestExport(self, addr: int) -> str:
        """Nearest export at or below `addr` as module!symbol+offset, or "".

        Bisects a sorted address list rather than scanning the exports map: this runs for
        every call stack frame on every break, and a fully loaded process has tens of
        thousands of exports.
        """
        if not self.exports:
            return ""

        if len(self.exportAddrs) != len(self.exports):
            self.exportAddrs = sorted(self.exports)

        exact = self.exports.get(addr)
        if exact:
            return exact

        idx = bisect.bisect_right(self.exportAddrs, addr)
        if not idx:
            return ""

        base = self.exportAddrs[idx - 1]
        if addr - base >= 0x10000:
            return ""

        return f"{self.exports[base]}+{addr - base:#x}"

    def ModuleNameFor(self, addr: int) -> str:
        """The module containing `addr`, for frames with no matching export."""
        idx = bisect.bisect_right(self.moduleRanges, (addr,))
        if idx:
            start, end, modName = self.moduleRanges[idx - 1]
            if start <= addr < end:
                return modName

        return ""

    def HandleStackUpdate(self, payload):
        if payload.startswith("Failed"):
            log.warning("[DEBUG CONSOLE] Stack: %s", payload)
            return

        self.UpdateStack(payload)

    def HandleConsoleOutput(self, payload):
        self.AppendConsole(payload)

    def HandleExecution(self, payload):
        if "TIMEOUT" in payload:
            self.AppendConsole(payload)
            self.disassemblyConsole.ClearHighlight()
            log.debug("[DEBUG] Execution fault detected, refreshing PageMap...")
            # The layout the retained pages were read under is no longer trustworthy.
            self.pageBuffers.clear()

            self.RefreshPageMap()
            self.RefreshModuleList()
            return

        m = re.search(r"0x[0-9a-fA-F]+", payload)
        if m:
            cip = int(m.group(0), 16)
            self.cip = cip
            self.AppendConsole(payload)
            if not self.IsAddressKnown(cip):
                self.RefreshPageMap()
                self.RefreshModuleList()
                return

            self.JumpTo(cip)
        else:
            log.error("[DEBUG CONSOLE] Failed to parse CIP from payload: %s", payload)

    def HandleNopInstruction(self, payload):
        if payload.startswith("Failed"):
            log.warning("[DEBUG CONSOLE] NopInstruction: %s", payload)

        self.JumpTo(self.cip)

    def HandlePatchBytes(self, payload):
        if payload.startswith("Failed"):
            log.warning("[DEBUG CONSOLE] PatchBytes: %s", payload)

        self.JumpTo(self.cip)
