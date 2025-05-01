import logging
import re
import threading
from collections import deque

import pywintypes
import win32event
import win32file
import wx
import wx.dataview as dv

from CAPEsolo.lib.core.pipe import PipeDispatcher, PipeServer, disconnect_pipes

log = logging.getLogger(__name__)

TIMEOUT = 600
BUFFER_SIZE = 4096
DBGCMD = "DBGCMD"


class StackModel(dv.PyDataViewIndexListModel):

    def __init__(self, data):
        super().__init__(len(data))
        self.data = data
        self.hilightRow = -1

    def GetColumnCount(self):
        return 3

    def GetColumnType(self, col):
        return "string"

    def GetValueByRow(self, row, col):
        return self.data[row][col]

    def GetCount(self):
        return len(self.data)

    def GetAttr(self, row, col, attr):
        if row == self.hilightRow:
            attr.SetBackgroundColour(wx.Colour(211, 211, 211))
            return True
        return False


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
                notified = self.console.breakCondition.wait_for(
                    lambda: self.console.pendingCommand is not None, timeout=TIMEOUT
                )
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
                notified = self.console.breakCondition.wait_for(
                    lambda: self.console.debuggerResponse, timeout=TIMEOUT
                )
                if notified:
                    response = b":" + self.console.debuggerResponse
                    self.console.debuggerResponse = None
                    return response
                else:
                    return b":TIMEOUT"
            else:
                self.console.pendingCommand = data
                self.console.breakCondition.notify_all()
                notified = self.console.breakCondition.wait_for(
                    lambda: self.console.debuggerResponse is not None, timeout=TIMEOUT
                )
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
            log.critical(
                "Unknown command received from the debug server: %s", data.strip()
            )
        else:
            command, arguments = data.strip().split(b":", 1)
            # log.info((command, data, "console dispatch"))
            fn = getattr(self, f"_handle_{command.lower().decode()}", None)
            if not fn:
                log.critical(
                    "Unknown command received from the debug server: %s", data.strip()
                )
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
        self.frame = ConsoleFrame(
            self, self.title, self.windowPosition, self.windowSize
        )
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
        self.Bind(
            wx.EVT_MENU, lambda evt: self.panel.SendCommand("S"), id=self.ID_STEP_INTO
        )
        self.Bind(
            wx.EVT_MENU, lambda evt: self.panel.SendCommand("O"), id=self.ID_STEP_OVER
        )
        self.Bind(
            wx.EVT_MENU, lambda evt: self.panel.SendCommand("C"), id=self.ID_CONTINUE
        )

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
        self.maxHistory = 512
        self.stackHistory = deque(maxlen=self.maxHistory)
        self.stackSet = set()
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

        # Disassembly
        mainSizer.Add(wx.StaticText(self, label="Disassembly"), 0, wx.ALL, 5)
        self.disasmDisplay = wx.TextCtrl(self, style=wx.TE_MULTILINE | wx.TE_READONLY)
        mainSizer.Add(self.disasmDisplay, 1, wx.EXPAND | wx.ALL, 5)
       '
        # Stack Frames
        mainSizer.Add(wx.StaticText(self, label="Stack Frames"), 0, wx.ALL, 5)
        self.stack_display = wx.TextCtrl(self, style=wx.TE_MULTILINE | wx.TE_READONLY)
        mainSizer.Add(self.stack_display, 1, wx.EXPAND | wx.ALL, 5)

        # Memory Watch
        mainSizer.Add(wx.StaticText(self, label="Memory Watch"), 0, wx.ALL, 5)
        self.memory_watch_list = wx.ListBox(self)
        mainSizer.Add(self.memory_watch_list, 1, wx.EXPAND | wx.ALL, 5)

        # Breakpoints
        mainSizer.Add(wx.StaticText(self, label="Breakpoints"), 0, wx.ALL, 5)
        self.breakpoints_list = wx.ListBox(self)
        mainSizer.Add(self.breakpoints_list, 1, wx.EXPAND | wx.ALL, 5)
        self.breakpoints_list.Bind(wx.EVT_LISTBOX_DCLICK, self.breakpoint)
        """

        self.hilightAttr = wx.TextAttr()
        self.hilightAttr.SetBackgroundColour(wx.Colour(211, 211, 211))
        fontCourier = wx.Font(
            10, wx.FONTFAMILY_MODERN, wx.FONTSTYLE_NORMAL, wx.FONTWEIGHT_NORMAL
        )
        topSizer = wx.BoxSizer(wx.HORIZONTAL)

        # Console Output
        consoleSizer = wx.BoxSizer(wx.VERTICAL)
        consoleSizer.Add(wx.StaticText(self, label="Console Output"), 0, wx.ALL, 5)
        self.outputConsole = wx.TextCtrl(self, style=wx.TE_MULTILINE | wx.TE_READONLY)
        self.outputConsole.SetFont(fontCourier)
        consoleSizer.Add(self.outputConsole, 2, wx.EXPAND | wx.ALL, 5)
        topSizer.Add(consoleSizer, 7, wx.EXPAND)

        # Registers
        regsSizer = wx.BoxSizer(wx.VERTICAL)
        regsSizer.Add(wx.StaticText(self, label="Registers"), 0, wx.ALL, 5)
        self.regsDisplay = wx.TextCtrl(self, style=wx.TE_MULTILINE | wx.TE_READONLY)
        self.regsDisplay.SetFont(fontCourier)
        regsSizer.Add(self.regsDisplay, 1, wx.EXPAND | wx.ALL, 5)
        topSizer.Add(regsSizer, 3, wx.EXPAND)

        mainSizer.Add(topSizer, 1, wx.EXPAND)

        bottomSizer = wx.BoxSizer(wx.HORIZONTAL)

        # Memory Dump
        memSizer = wx.BoxSizer(wx.VERTICAL)
        memSizer.Add(wx.StaticText(self, label="Memory Dump"), 0, wx.ALL, 5)
        self.memDumpDisplay = wx.TextCtrl(self, style=wx.TE_MULTILINE | wx.TE_READONLY)
        self.memDumpDisplay.SetFont(fontCourier)
        memSizer.Add(self.memDumpDisplay, 2, wx.EXPAND | wx.ALL, 5)

        # Address input field
        memSizer.Add(
            wx.StaticText(self, label="Memory Dump Address:"), 0, wx.LEFT | wx.TOP, 5
        )
        self.memAddressInput = wx.TextCtrl(self, style=wx.TE_PROCESS_ENTER)
        self.memAddressInput.SetFont(fontCourier)
        memSizer.Add(self.memAddressInput, 0, wx.EXPAND | wx.ALL, 5)
        self.memAddressInput.Bind(wx.EVT_TEXT_ENTER, self.OnAddressEnter)
        bottomSizer.Add(memSizer, 5, wx.EXPAND)

        # Stack
        stackSizer = wx.BoxSizer(wx.VERTICAL)
        self.stackDisplay = dv.DataViewCtrl(
            self, style=dv.DV_ROW_LINES | dv.DV_VERT_RULES | dv.DV_MULTIPLE
        )
        self.stackModel = StackModel(list(self.stackHistory))
        self.stackDisplay.AssociateModel(self.stackModel)
        self.stackDisplay.AppendTextColumn(
            "Address", 0, width=150, mode=dv.DATAVIEW_CELL_INERT
        )
        self.stackDisplay.AppendTextColumn(
            "Value", 1, width=150, mode=dv.DATAVIEW_CELL_INERT
        )
        self.stackDisplay.AppendTextColumn(
            "String", 2, width=200, mode=dv.DATAVIEW_CELL_INERT
        )
        self.stackDisplay.SetFont(fontCourier)

        stackSizer.Add(wx.StaticText(self, label="Stack"), 0, wx.ALL, 5)
        stackSizer.Add(self.stackDisplay, 1, wx.EXPAND | wx.ALL, 5)
        bottomSizer.Add(stackSizer, 5, wx.EXPAND)
        mainSizer.Add(bottomSizer, 1, wx.EXPAND)

        # Status Bar
        self.statusBar = wx.StaticText(self, label="Status: Disconnected")
        mainSizer.Add(self.statusBar, 0, wx.EXPAND | wx.ALL, 5)

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
            # cap the width (height left at default)
            btn.SetMinSize(wx.Size(MAX_BTN_W, -1))
            btn.Bind(wx.EVT_BUTTON, lambda evt, c=cmd: self.SendCommand(c))
            debugButtons.Add(btn, 0, wx.ALL | wx.ALIGN_CENTER_VERTICAL, 5)

        # shove any leftover space to the right
        debugButtons.AddStretchSpacer()
        mainSizer.Add(debugButtons, 0, wx.EXPAND | wx.LEFT | wx.RIGHT | wx.BOTTOM, 5)

        # Input box
        mainSizer.Add(wx.StaticText(self, label="Command Input"), 0, wx.ALL, 5)
        self.inputBox = wx.TextCtrl(self, style=wx.TE_PROCESS_ENTER)
        self.inputBox.Bind(wx.EVT_TEXT_ENTER, self.OnEnter)
        mainSizer.Add(self.inputBox, 0, wx.EXPAND | wx.ALL, 5)

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

    def AppendOutput(self, text):
        """Appends text to the output console."""
        self.outputConsole.AppendText(text + "\n")

    def UpdateOutput(self, text):
        self.AppendOutput(text)
        self.SendCommand("N")
        self.SendCommand("N")
        self.SendCommand("N")
        self.SendCommand("R")
        self.SendCommand("M")
        self.SendCommand("K")

    def UpdateRegs(self, text):
        """Update registers display."""
        self.regsDisplay.Clear()
        self.regsDisplay.SetValue(text)

    def UpdateStack(self, data):
        """Update stack display."""
        for line in data.splitlines():
            parts = [p.strip() for p in line.split(",", 2)]
            if len(parts) < 2:
                continue
            addr, val = parts[0], parts[1]
            asciiStr = parts[2] if len(parts) == 3 else ""

            if addr in self.stackSet:
                for i, tpl in enumerate(self.stackHistory):
                    if tpl[0] == addr:
                        self.stackHistory[i] = (addr, val, asciiStr)
                        break
            else:
                if len(self.stackHistory) == self.maxHistory:
                    old = self.stackHistory.popleft()
                    self.stackSet.remove(old[0])
                self.stackHistory.append((addr, val, asciiStr))
                self.stackSet.add(addr)

        self.stackModel.data = list(self.stackHistory)
        self.stackModel.Reset(len(self.stackHistory))

        regs = self.regsDisplay.GetValue()
        m = re.search(r"\b[ER]SP\s*=\s*(0x[0-9A-Fa-f]+)", regs)
        sp = m.group(1) if m else None
        spIdx = next(
            (i for i, (a, _, _) in enumerate(self.stackHistory) if a == sp),
            len(self.stackHistory) - 1,
        )

        self.stackModel.hilightRow = spIdx

        if self.stackHistory:
            first = self.stackModel.GetItem(0)
            rect = self.stackDisplay.GetItemRect(first)
            rowH = rect.height
            visRows = max(1, self.stackDisplay.GetClientSize().height // rowH)
        else:
            visRows = 1

        half = visRows // 2
        anchor = max(0, spIdx - half)
        anchorItem = self.stackModel.GetItem(anchor)
        self.stackDisplay.EnsureVisible(anchorItem)

    def UpdateMemDump(self, text):
        """Update memory dump display."""
        self.memDumpDisplay.Clear()
        self.memDumpDisplay.SetValue(text)

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
            threading.Thread(
                target=self.SendCommand, args=("init",), daemon=True
            ).start()
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
            self.AppendOutput(data)
            self.SendCommand("I")
        elif data == "TIMEOUT":
            self.AppendOutput("Operation timed out")
        else:
            if command == "R":
                self.UpdateRegs(data)
            elif command in ("N", "H", "B", "D"):
                self.AppendOutput(data)
            elif command == "I":
                self.UpdateOutput(data)
            elif command == "M":
                self.UpdateMemDump(data)
            elif command == "K":
                self.UpdateStack(data)
            elif command in ("O", "S", "C"):
                self.AppendOutput(data)
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
