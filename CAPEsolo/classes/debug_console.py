import logging
import threading

import pywintypes
import win32event
import win32file
import wx

from CAPEsolo.lib.core.pipe import PipeDispatcher, PipeServer, disconnect_pipes

log = logging.getLogger(__name__)

TIMEOUT = 600
BUFFER_SIZE = 4096
DBGCMD = "DBGCMD"


class CommandPipeHandler:
    """Handles messages received on the command pipe from the debug server."""
    def __init__(self, console):
        self.console = console

    def _handle_break(self, data):
        with self.console.breakCondition:
            if not data:
                self.console.debuggerResponse = b"BREAK"
                self.console.breakCondition.notify_all()
            else:
                self.console.debuggerResponse = data
                self.console.breakCondition.notify_all()
            if not self.console.pendingCommand:
                notified = self.console.breakCondition.wait_for(
                    lambda: self.console.pendingCommand is not None, timeout=TIMEOUT
                )
                if not notified:
                    self.console.pendingCommand = None
                    return b"TIMEOUT"
                command = self.console.pendingCommand
                self.console.pendingCommand = None
                return command

    def _handle_dbgcmd(self, data):
        with self.console.breakCondition:
            if data.lower() == b"init":
                notified = self.console.breakCondition.wait_for(
                    lambda: self.console.debuggerResponse == b"BREAK", timeout=TIMEOUT
                )
                if notified:
                    self.console.debuggerResponse = None
                    return b"READY"
                else:
                    return b"TIMEOUT"
            else:
                self.console.pendingCommand = data
                self.console.breakCondition.notify_all()
                notified = self.console.breakCondition.wait_for(
                    lambda: self.console.debuggerResponse is not None, timeout=TIMEOUT
                )
                if not notified:
                    self.console.pendingCommand = None
                    return b"TIMEOUT"
                response = self.console.debuggerResponse
                self.console.debuggerResponse = None
                return response

    def dispatch(self, data):
        response = b"NOPE"
        if not data or b":" not in data:
            log.critical("Unknown command received from the debug server: %s", data.strip())
        else:
            command, arguments = data.strip().split(b":", 1)
            #log.info((command, data, "console dispatch"))
            fn = getattr(self, f"_handle_{command.lower().decode()}", None)
            if not fn:
                log.critical("Unknown command received from the debug server: %s", data.strip())
            else:
                try:
                    response = fn(arguments)
                except Exception as e:
                    log.error(e, exc_info=True)
                    log.exception("Pipe command handler exception (command %s args %s)", command, arguments)
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
        self.connected = False
        self.read_lock = threading.Lock()
        self.InitGUI()
        wx.CallLater(100, self.InitPipe)

    def InitGUI(self):
        # Main Layout
        mainSizer = wx.BoxSizer(wx.VERTICAL)

        # Console Output
        mainSizer.Add(wx.StaticText(self, label="Console Output"), 0, wx.ALL, 5)
        self.outputConsole = wx.TextCtrl(self, style=wx.TE_MULTILINE | wx.TE_READONLY)
        mainSizer.Add(self.outputConsole, 2, wx.EXPAND | wx.ALL, 5)

        # Status Bar
        self.statusBar = wx.StaticText(self, label="Status: Disconnected")
        mainSizer.Add(self.statusBar, 0, wx.EXPAND | wx.ALL, 5)
        '''
        # Threads
        mainSizer.Add(wx.StaticText(self, label="Active Threads"), 0, wx.ALL, 5)
        self.thread_list = wx.ListBox(self)
        mainSizer.Add(self.thread_list, 1, wx.EXPAND | wx.ALL, 5)
        self.thread_list.Bind(wx.EVT_LISTBOX, self.switch_thread)

        # Registers
        mainSizer.Add(wx.StaticText(self, label="Registers"), 0, wx.ALL, 5)
        self.registers_display = wx.TextCtrl(self, style=wx.TE_MULTILINE | wx.TE_READONLY)
        mainSizer.Add(self.registers_display, 1, wx.EXPAND | wx.ALL, 5)

        # Stack Frames
        mainSizer.Add(wx.StaticText(self, label="Stack Frames"), 0, wx.ALL, 5)
        self.stack_display = wx.TextCtrl(self, style=wx.TE_MULTILINE | wx.TE_READONLY)
        mainSizer.Add(self.stack_display, 1, wx.EXPAND | wx.ALL, 5)

        # Memory Watch
        mainSizer.Add(wx.StaticText(self, label="Memory Watch"), 0, wx.ALL, 5)
        self.memory_watch_list = wx.ListBox(self)
        mainSizer.Add(self.memory_watch_list, 1, wx.EXPAND | wx.ALL, 5)

        # Disassembly
        mainSizer.Add(wx.StaticText(self, label="Disassembly"), 0, wx.ALL, 5)
        self.disasm_display = wx.TextCtrl(self, style=wx.TE_MULTILINE | wx.TE_READONLY)
        mainSizer.Add(self.disasm_display, 1, wx.EXPAND | wx.ALL, 5)

        # Breakpoints
        mainSizer.Add(wx.StaticText(self, label="Breakpoints"), 0, wx.ALL, 5)
        self.breakpoints_list = wx.ListBox(self)
        mainSizer.Add(self.breakpoints_list, 1, wx.EXPAND | wx.ALL, 5)
        self.breakpoints_list.Bind(wx.EVT_LISTBOX_DCLICK, self.toggle_breakpoint)
        '''
        # Debugging Controls
        debugButtons = wx.BoxSizer(wx.HORIZONTAL)
        self.stepIntoBtn = wx.Button(self, label="Step Into (F7)")
        self.stepOverBtn = wx.Button(self, label="Step Over (F8)")
        self.continueBtn = wx.Button(self, label="Continue (F10)")
        debugButtons.Add(self.stepIntoBtn, 1, wx.EXPAND | wx.ALL, 5)
        debugButtons.Add(self.stepOverBtn, 1, wx.EXPAND | wx.ALL, 5)
        debugButtons.Add(self.continueBtn, 1, wx.EXPAND | wx.ALL, 5)
        self.stepIntoBtn.Bind(wx.EVT_BUTTON, lambda event: self.SendCommand("step_into"))
        self.stepOverBtn.Bind(wx.EVT_BUTTON, lambda event: self.SendCommand("step_over"))
        self.continueBtn.Bind(wx.EVT_BUTTON, lambda event: self.SendCommand("continue"))
        self.Bind(wx.EVT_CHAR_HOOK, self.OnKeyDown)
        mainSizer.Add(debugButtons, 0, wx.EXPAND | wx.ALL, 5)

        # Input box
        mainSizer.Add(wx.StaticText(self, label="Command Input"), 0, wx.ALL, 5)
        self.inputBox = wx.TextCtrl(self, style=wx.TE_PROCESS_ENTER)
        self.inputBox.Bind(wx.EVT_TEXT_ENTER, self.OnEnter)
        mainSizer.Add(self.inputBox, 0, wx.EXPAND | wx.ALL, 5)

        self.SetSizer(mainSizer)

    def OnKeyDown(self, event):
        if event.GetKeyCode() == ord("F7") and event.ControlDown():
            self.SendCommand("step_into")
        elif event.GetKeyCode() == ord("F8") and event.ControlDown():
            self.SendCommand("step_over")
        elif event.GetKeyCode() == ord("F10") and event.ControlDown():
            self.SendCommand("continue")
        else:
            event.Skip()

    def AppendOutput(self, text):
        """Appends text to the output console and logs it."""
        if self.outputConsole:
            self.outputConsole.AppendText(text + "\n")

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
                None
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

    def ProcessServerOutput(self, text):
        """Processes debugger responses."""
        '''
        if "THREADS" in text:
            print("threads:", text)
            threads = text.replace("THREADS", "").strip().split("\n")
            wx.CallAfter(self.thread_list.Clear)
            for thread in threads:
                wx.CallAfter(self.thread_list.Append, f"Thread {thread}")
        elif "REGISTERS" in text:
            wx.CallAfter(self.registers_display.SetValue, text.replace("REGISTERS", ""))
        elif "STACK" in text:
            wx.CallAfter(self.stack_display.SetValue, text.replace("STACK", ""))
        elif "DISASM" in text:
            wx.CallAfter(self.disasm_display.SetValue, text.replace("DISASM", ""))
        elif "MEMORY" in text:
            mem_data = text.replace("MEMORY", "").strip().split("\n")
            wx.CallAfter(self.memory_watch_list.Clear)
            for mem in mem_data:
                wx.CallAfter(self.memory_watch_list.Append, mem)
        elif "BREAKPOINTS" in text:
            mem_data = text.replace("BREAKPOINTS", "").strip().split("\n")
            wx.CallAfter(self.breakpoints_list.Clear)
            for mem in mem_data:
                wx.CallAfter(self.breakpoints_list.Append, mem)
        else:
        '''
        if text == "READY":
            self.connected = True
            self.UpdateStatus("Status: Connected")
            if not self.parent.IsShown():
                self.parent.Show()
                self.parent.Layout()
            self.AppendOutput("Debugger initialized")
        elif text == "TIMEOUT":
            self.AppendOutput("Operation timed out")
        else:
            self.AppendOutput(text)

    def ReadResponse(self):
        """Reads a full response from the pipe in a thread-safe manner."""
        with self.read_lock:
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

    def SendCommand(self, command):
        if command.lower() != "init" and (not self.connected or not self.pipeHandle):
            log.error("[DEBUG CONSOLE] Cannot send command: Not connected to pipe")
            return

        fullCommand = f"{DBGCMD}:{command}".encode("utf-8") + b"\n"
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

    '''
    def switch_thread(self, event):
        """Switches the active thread for debugging."""
        selection = self.thread_list.GetSelection()
        if selection != wx.NOT_FOUND:
            thread_id = self.thread_list.GetString(selection).split()[-1]
            self.send_command(f"thread select {thread_id}")

    def toggle_breakpoint(self, event):
        """Toggles the selected breakpoint on/off."""
        selection = self.breakpoints_list.GetSelection()
        if selection != wx.NOT_FOUND:
            bp_text = self.breakpoints_list.GetString(selection)
            if "(disabled)" in bp_text:
                self.breakpoints_list.SetString(selection, bp_text.replace(" (disabled)", ""))
                self.send_command(f"break enable {bp_text.split()[-1]}")
            else:
                self.breakpoints_list.SetString(selection, bp_text + " (disabled)")
                self.send_command(f"break disable {bp_text.split()[-1]}")
    '''

    def OnEnter(self, event):
        """Handles user input and processes commands."""
        cmd = self.inputBox.GetValue().strip()
        if cmd.lower() == "disconnect":
            wx.CallAfter(self.statusBar.SetLabel, "Status: Disconnected")
            win32file.CloseHandle(self.pipeHandle)
            self.connected = False
            log.info("[DEBUG CONSOLE] Pipe disconnected successfully.")
        elif cmd.lower() == "quit":
            self.ShutdownConsole()
        elif cmd.lower() == "clear":
            self.outputConsole.Clear()
        else:
            self.SendCommand(cmd)

        self.inputBox.Clear()

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
