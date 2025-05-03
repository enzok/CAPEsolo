import logging
import re
import threading

import pywintypes
import win32event
import win32file
import wx

from CAPEsolo.lib.core.pipe import PipeDispatcher, PipeServer, disconnect_pipes

log = logging.getLogger(__name__)

TIMEOUT = 600
BUFFER_SIZE = 0x10000
DBGCMD = "DBGCMD"


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
        spVal = m.group(2) if m else None
        spIdx = len(rows) // 2
        if spVal:
            for i, (addr, _) in enumerate(rows):
                if addr.lower() == spVal.lower():
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


class ConsoleListCtrl(wx.ListCtrl):
    def __init__(self, parent):
        super().__init__(parent, style=wx.LC_REPORT | wx.LC_SINGLE_SEL)
        self.parent = parent
        self.InsertColumn(0, "Address", width=170)
        self.InsertColumn(1, "Hex Dump", width=170)
        self.InsertColumn(2, "Disassembly", width=300)
        self.data = []
        self.highlightedIdx = None

    def UpdateData(self, data):
        """Populate the list control from a string of lines."""
        for line in data.splitlines():
            parts = [p.strip() for p in line.split(",", 2)]

            if not parts:
                continue

            addr = parts[0]
            hexstr = parts[1] if len(parts) > 1 else ""
            disasm = parts[2] if len(parts) > 2 else ""
            row = (addr, hexstr, disasm)
            if row not in self.data:
                self.data.append(row)
                idx = self.InsertItem(self.GetItemCount(), addr)
                self.SetItem(idx, 1, hexstr)
                self.SetItem(idx, 2, disasm)

        self.Refresh()
        self.EnsureVisible(len(data) - 1)

    def HighlightIp(self):
        highlightIdx = 0
        regsText = self.parent.regsDisplay.GetValue()
        m = re.search(r"\b([ER]IP):\s*([0-9A-Fa-f]+)", regsText)
        ipVal = m.group(2) if m else None

        if ipVal:
            for i, (addr, _, _) in enumerate(self.data):
                if addr.lower() == ipVal.lower():
                    highlightIdx = i
                    break

        if self.highlightedIdx is not None:
            self.SetItemBackgroundColour(self.highlightedIdx, wx.Colour(255, 255, 255))

        self.SetItemBackgroundColour(highlightIdx, wx.Colour(211, 211, 211))
        self.highlightedIdx = highlightIdx
        self.Refresh()


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
            log.critical("Unknown command received from the debug server: %s", data.strip())
        else:
            command, arguments = data.strip().split(b":", 1)
            # log.info((command, data, "console dispatch"))
            fn = getattr(self, f"_handle_{command.lower().decode()}", None)
            if not fn:
                log.critical("Unknown command received from the debug server: %s", data.strip())
            else:
                try:
                    response = fn(arguments)
                    log.info(response)
                except Exception as e:
                    log.error(e, exc_info=True)
                    log.exception(
                        "Pipe command handler exception (command %s args %s)",
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
        self.disassemblyConsole = ConsoleListCtrl(self)
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

    def AppendOutput(self, data):
        """Appends text to the output console."""
        self.disassemblyConsole.UpdateData(data)
        #self.disassemblyConsole.UpdateData(data)

    def AppendConsole(self, text):
        """Appends text to the output console."""
        self.outputConsole.AppendText(text + "\n")

    def UpdateOutput(self, text):
        self.AppendOutput(text)
        self.SendCommand("R")
        self.SendCommand("N")
        self.disassemblyConsole.HighlightIp()
        if self.initMemdmp:
            self.SendCommand("M")
            self.initMemdmp = False
        else:
            addr = self.memDumpDisplay.GetFirstHexAddress()
            self.memAddressInput.SetValue(addr)
            self.OnAddressEnter(wx.CommandEvent(wx.EVT_TEXT_ENTER.typeId, self.memAddressInput.GetId()))

        self.SendCommand("K")

    def UpdateRegs(self, text):
        """Update registers display."""
        self.regsDisplay.Clear()
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

    def ProcessServerOutput(self, data):
        """Processes debugger responses."""
        command, data = data.split(":", 1)
        if data and not self.connected:
            self.connected = True
            self.UpdateStatus("Status: Connected")
            if not self.parent.IsShown():
                self.parent.Show()
                self.parent.Layout()
            self.AppendConsole(data)
            self.SendCommand("I")
        elif data == "TIMEOUT":
            self.AppendConsole("Operation timed out")
        else:
            if command == "R":
                self.UpdateRegs(data)
            elif command == "N":
                self.AppendOutput(data)
            elif command in ("H", "B", "D"):
                self.AppendConsole(data)
            elif command == "I":
                self.UpdateOutput(data)
            elif command == "M":
                self.UpdateMemDump(data)
            elif command == "K":
                self.UpdateStack(data)
            elif command in ("O", "S", "C"):
                self.AppendConsole(data)
                self.SendCommand("I")
            else:
                log.error("[DEBUG CONSOLE] Invalid command: %s", command)

    def ReadResponse(self):
        """Reads a full response from the pipe in a thread-safe manner."""
        with self.readLock:
            try:
                # Read up to BUFFER_SIZE bytes; adjust if needed.
                result, data = win32file.ReadFile(self.pipeHandle, BUFFER_SIZE)
                response = data.decode("utf-8").strip()
                return response
            except Exception as e:
                log.error("Error reading response: %s", e)
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

