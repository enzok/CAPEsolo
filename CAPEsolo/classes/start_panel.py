import hashlib
import logging
import os
import shutil
from datetime import datetime
from pathlib import Path
from threading import Thread

import wx
from sflock.abstracts import File as SflockFile
from sflock.ident import identify as sflock_identify

from CAPEsolo.capelib.resultserver import ResultServer
from CAPEsolo.capelib.utils import sanitize_filename
from CAPEsolo.lib.common.hashing import hash_file
from .key_event import EVT_ANALYZER_COMPLETE_ID, EVT_ANALYZER_COMPLETE
from .logger_window import LoggerWindow
from .timer_window import CountdownTimer

log = logging.getLogger(__name__)

SANDBOXPACKAGES = (
    "Shellcode",
    "Shellcode_trace",
    "Shellcode_x64",
    "Shellcode_x64_trace",
    "archive",
    "chm",
    "dll",
    "doc",
    "exe",
    "hta",
    "iso",
    "jar",
    "js",
    "lnk",
    "mht",
    "msi",
    "msix",
    "nsis",
    "ps1",
    "pub",
    "python",
    "rar",
    "regsvr",
    "sct",
    "service",
    "service_dll",
    "udf",
    "vhd",
    "xls",
    "xps",
    "xslt",
    "zip",
)

DEBUGACTIONS = [
    "dump",
    "dumpimage",
    "jmp",
    "scan",
    "skip",
    "sleep",
    "setbp",
    "setdump",
    "setdst" "setsrc",
]


def GetPreviousTarget(analysisDir):
    for path in Path(analysisDir).glob("s_*"):
        if path.is_file():
            return path
    return None


class AnalyzerCompleteEvent(wx.PyCommandEvent):
    def __init__(self, etype, eid, message=None):
        super(AnalyzerCompleteEvent, self).__init__(etype, eid)
        self.message = message


class StartPanel(wx.Panel):
    def __init__(self, parent):
        super().__init__(parent)
        self.parent = parent
        self.curDir = True
        self.manualExecution = False
        self.enforceTimeout = False
        self.analysisDir = parent.analysisDir
        self.analysisLogPath = os.path.join(parent.analysisDir, "analysis.log")
        self.package = ""
        self.capesoloRoot = parent.capesoloRoot
        self.targetFile = GetPreviousTarget(self.analysisDir)
        self.parent.targetFile = self.targetFile
        self.timer = None
        self.InitUi()
        self.LoadAnalysisConfFile()
        self.Bind(EVT_ANALYZER_COMPLETE, self.OnAnalyzerComplete)

    def InitUi(self):
        vbox = wx.BoxSizer(wx.VERTICAL)

        # File Dropdown and Browse Button
        hbox1 = wx.BoxSizer(wx.HORIZONTAL)
        self.targetPath = wx.TextCtrl(self)
        self.targetPath.SetValue("<Target file>")
        browseBtn = wx.Button(self, label="Browse...")
        browseBtn.Bind(wx.EVT_BUTTON, self.OnBrowse)
        hbox1.Add(self.targetPath, proportion=1, flag=wx.EXPAND | wx.RIGHT, border=5)
        hbox1.Add(browseBtn, proportion=0)

        hbox2 = wx.BoxSizer(wx.HORIZONTAL)
        packageLabel = wx.StaticText(self, label="Packages")
        self.packageDropdown = wx.ComboBox(self, style=wx.CB_READONLY)
        self.PackageDropdown()
        self.packageDropdown.SetValue("Auto-detect")
        self.runFromCurrentDirCheckbox = wx.CheckBox(
            self, label="Run sample from current directory"
        )
        self.runFromCurrentDirCheckbox.Bind(
            wx.EVT_CHECKBOX, self.OnCurrentDirCheckboxClick
        )
        self.runFromCurrentDirCheckbox.SetValue(True)
        self.manualExecutionCheckbox = wx.CheckBox(self, label="Manual Execution")
        self.manualExecutionCheckbox.Bind(
            wx.EVT_CHECKBOX, self.OnManualExecCheckboxClick
        )
        self.manualExecutionCheckbox.SetValue(False)
        hbox2.Add(packageLabel, flag=wx.RIGHT | wx.ALIGN_CENTER_VERTICAL, border=10)
        hbox2.Add(
            self.packageDropdown, proportion=0, flag=wx.EXPAND | wx.RIGHT, border=10
        )
        hbox2.Add(self.runFromCurrentDirCheckbox, flag=wx.ALIGN_CENTER_VERTICAL)
        hbox2.Add(self.manualExecutionCheckbox, flag=wx.ALIGN_CENTER_VERTICAL)

        # Optional Arguments Input
        hbox3 = wx.BoxSizer(wx.HORIZONTAL)
        argsLabel = wx.StaticText(self, label="Options")
        self.optionsCtrl = wx.TextCtrl(
            self,
            value="option1=value, option2=value, etc...",
            style=wx.TE_PROCESS_ENTER,
        )
        self.optionsCtrl.Bind(wx.EVT_LEFT_DOWN, self.OnOptionInputClick)
        self.optionsCtrl.Bind(wx.EVT_KILL_FOCUS, self.OnOptionInputFocus)
        hbox3.Add(argsLabel, flag=wx.RIGHT, border=5)
        hbox3.Add(self.optionsCtrl, proportion=1, flag=wx.EXPAND)

        # Enforce Timeout Checkbox and Timeout Input
        hboxTimeout = wx.BoxSizer(wx.HORIZONTAL)
        self.enforceTimeoutCheckbox = wx.CheckBox(self, label="Enforce timeout")
        self.enforceTimeoutCheckbox.Bind(
            wx.EVT_CHECKBOX, self.OnEnforceTimeoutCheckboxClick
        )
        self.enforceTimeoutCheckbox.SetValue(False)
        msLabel = wx.StaticText(self, label=" seconds")
        self.timeoutInput = wx.TextCtrl(self, size=(50, -1), value="200")
        hboxTimeout.Add(
            self.enforceTimeoutCheckbox,
            flag=wx.RIGHT | wx.ALIGN_CENTER_VERTICAL,
            border=5,
        )
        hboxTimeout.Add(self.timeoutInput, flag=wx.ALIGN_CENTER_VERTICAL)
        hboxTimeout.Add(msLabel, flag=wx.RIGHT | wx.ALIGN_CENTER_VERTICAL, border=5)

        # analysis.conf editor
        analysisConfSizer = wx.BoxSizer(wx.VERTICAL)
        self.analysisConfExpander = wx.CollapsiblePane(
            self, label="analysis.conf"
        )
        self.analysisConfExpander.Bind(
            wx.EVT_COLLAPSIBLEPANE_CHANGED, self.OnCollapsiblePaneChanged
        )
        self.analysisConfExpander.GetPane().SetMinSize(self.GetSize())
        analysisConfPane = self.analysisConfExpander.GetPane()
        self.analysisEditor = wx.TextCtrl(
            analysisConfPane, style=wx.TE_MULTILINE, size=self.GetSize()
        )
        analysisConfSizer.Add(
            self.analysisConfExpander, proportion=1, flag=wx.EXPAND | wx.ALL, border=0
        )
        analysisConfPaneSizer = wx.BoxSizer(wx.VERTICAL)
        analysisConfPaneSizer.Add(
            self.analysisEditor, proportion=1, flag=wx.EXPAND | wx.ALL, border=0
        )
        analysisConfPane.SetSizer(analysisConfPaneSizer)
        self.analysisConfExpander.Collapse(True)
        self.OnCollapsiblePaneChanged(None)

        # Debugger Collapsible Pane
        self.debuggerCollapsePane = wx.CollapsiblePane(self, label="Debugger options")
        self.debuggerCollapsePane.Bind(
            wx.EVT_COLLAPSIBLEPANE_CHANGED, self.OnCollapsiblePaneChanged
        )
        self.debuggerPane = self.debuggerCollapsePane.GetPane()

        self.flexDebuggerSizer = wx.FlexGridSizer(rows=8, cols=2, hgap=10, vgap=10)
        self.flexDebuggerSizer.AddGrowableCol(1, 1)

        self.addrType0, self.addr0, self.action0, self.value0 = self.AddDebuggerControls(0)
        self.addrType1, self.addr1, self.action1, self.value1 = self.AddDebuggerControls(1)
        self.addrType2, self.addr2, self.action2, self.value2 = self.AddDebuggerControls(2)
        self.addrType3, self.addr3, self.action3, self.value3 = self.AddDebuggerControls(3)

        hboxBaseApi = wx.BoxSizer(wx.HORIZONTAL)
        baseApiLabel = wx.StaticText(self.debuggerPane, label="base-on-api:")
        self.baseApi = wx.TextCtrl(self.debuggerPane, size=(100, -1))
        hboxBaseApi.Add(baseApiLabel, flag=wx.RIGHT | wx.ALIGN_CENTER_VERTICAL, border=5)
        hboxBaseApi.Add(self.baseApi, flag=wx.ALIGN_CENTER_VERTICAL)
        hboxBreakRet = wx.BoxSizer(wx.HORIZONTAL)
        breakRetLabel = wx.StaticText(self.debuggerPane, label="break-on-return:")
        self.apiList = wx.TextCtrl(self.debuggerPane, size=(250, -1))
        hboxBreakRet.Add(breakRetLabel, flag=wx.RIGHT | wx.ALIGN_CENTER_VERTICAL, border=5)
        hboxBreakRet.Add(self.apiList, flag=wx.ALIGN_CENTER_VERTICAL)
        hboxCount = wx.BoxSizer(wx.HORIZONTAL)
        countLabel = wx.StaticText(self.debuggerPane, label="Count:")
        self.debugCount = wx.TextCtrl(self.debuggerPane, size=(75, -1))
        hboxCount.Add(countLabel, flag=wx.RIGHT | wx.ALIGN_CENTER_VERTICAL, border=5)
        hboxCount.Add(self.debugCount, flag=wx.ALIGN_CENTER_VERTICAL)
        hboxDepth = wx.BoxSizer(wx.HORIZONTAL)
        depthLabel = wx.StaticText(self.debuggerPane, label="Depth:")
        self.debugDepth = wx.TextCtrl(self.debuggerPane, size=(50, -1))
        hboxDepth.Add(depthLabel, flag=wx.RIGHT | wx.ALIGN_CENTER_VERTICAL, border=5)
        hboxDepth.Add(self.debugDepth, flag=wx.ALIGN_CENTER_VERTICAL)
        self.flexDebuggerSizer.Add(
            hboxBaseApi, proportion=0, flag=wx.ALIGN_CENTER_VERTICAL | wx.RIGHT, border=5
        )
        self.flexDebuggerSizer.Add(
            hboxBreakRet, proportion=0, flag=wx.ALIGN_CENTER_VERTICAL | wx.RIGHT, border=5
        )
        self.flexDebuggerSizer.Add(
            hboxCount, proportion=0, flag=wx.ALIGN_CENTER_VERTICAL | wx.RIGHT, border=5
        )
        self.flexDebuggerSizer.Add(hboxDepth, proportion=0, flag=wx.EXPAND)

        debuggerVert = wx.BoxSizer(wx.VERTICAL)
        debuggerVert.Add(self.flexDebuggerSizer, proportion=0, border=1)
        self.debuggerPane.SetSizer(debuggerVert)

        # Launch and kill
        hbox5 = wx.BoxSizer(wx.HORIZONTAL)
        self.launchAnalyzerBtn = wx.Button(self, label="Launch")
        self.launchAnalyzerBtn.Disable()
        self.launchAnalyzerBtn.Bind(wx.EVT_BUTTON, self.OnLaunchAnalyzer)

        openDirBtn = wx.Button(self, label="View Analysis Directory")
        openDirBtn.Bind(wx.EVT_BUTTON, self.OnOpenDirectory)
        self.terminateAnalyzerBtn = wx.Button(self, label="Kill")
        self.terminateAnalyzerBtn.Disable()
        self.terminateAnalyzerBtn.Bind(wx.EVT_BUTTON, self.OnTerminateAnalyzer)
        hbox5.Add(
            self.launchAnalyzerBtn, proportion=0, flag=wx.EXPAND | wx.RIGHT, border=5
        )

        hbox5.AddStretchSpacer(1)
        hbox5.Add(openDirBtn, proportion=0, flag=wx.EXPAND | wx.RIGHT, border=5)
        hbox5.Add(self.terminateAnalyzerBtn, proportion=0, flag=wx.EXPAND)
        self.terminateAnalyzerBtn.Disable()

        # Layout
        vbox.Add(hbox1, flag=wx.EXPAND | wx.ALL, border=10)
        vbox.Add(hbox2, flag=wx.EXPAND | wx.LEFT | wx.RIGHT | wx.BOTTOM, border=10)
        vbox.Add(hbox3, flag=wx.EXPAND | wx.LEFT | wx.RIGHT | wx.BOTTOM, border=10)
        vbox.Add(
            hboxTimeout, flag=wx.EXPAND | wx.LEFT | wx.RIGHT | wx.BOTTOM, border=10
        )
        vbox.Add(
            self.debuggerCollapsePane,
            flag=wx.EXPAND | wx.LEFT | wx.RIGHT | wx.BOTTOM,
            border=10,
        )
        vbox.Add(analysisConfSizer, proportion=1, flag=wx.EXPAND | wx.ALL, border=10)
        vbox.Add(
            wx.StaticLine(self, style=wx.LI_HORIZONTAL),
            flag=wx.EXPAND | wx.LEFT | wx.RIGHT | wx.BOTTOM,
            border=10,
        )
        vbox.Add(hbox5, flag=wx.EXPAND | wx.LEFT | wx.RIGHT | wx.BOTTOM, border=10)

        self.SetSizer(vbox)

    def AddDebuggerControls(self, index):
        hboxBp = wx.BoxSizer(wx.HORIZONTAL)
        bpLabel = wx.StaticText(self.debuggerPane, label=f"bp{index}")
        addrTypeDropdown = wx.ComboBox(
            self.debuggerPane, style=wx.CB_READONLY, choices=["RVA", "VA"], value="RVA"
        )
        hexLabel = wx.StaticText(self.debuggerPane, label=f": 0x")
        addrTextCtrl = wx.TextCtrl(self.debuggerPane, size=(75, -1))
        hboxBp.Add(
            bpLabel, proportion=0, flag=wx.ALIGN_CENTER_VERTICAL | wx.RIGHT, border=5
        )
        hboxBp.Add(
            addrTypeDropdown,
            proportion=0,
            flag=wx.ALIGN_CENTER_VERTICAL | wx.RIGHT,
            border=0,
        )
        hboxBp.Add(
            hexLabel, proportion=0, flag=wx.ALIGN_CENTER_VERTICAL | wx.RIGHT, border=0
        )
        hboxBp.Add(addrTextCtrl, proportion=0, flag=wx.EXPAND)

        hboxAction = wx.BoxSizer(wx.HORIZONTAL)
        actionLabel = wx.StaticText(self.debuggerPane, label=f"action{index}:")
        actionDropdown = wx.ComboBox(
            self.debuggerPane, style=wx.CB_READONLY, choices=[""]
        )
        actionDropdown.AppendItems(DEBUGACTIONS)
        colon = wx.StaticText(self.debuggerPane, label=":")
        valueTextCtrl = wx.TextCtrl(self.debuggerPane, size=(100, -1))
        hboxAction.Add(
            actionLabel,
            proportion=0,
            flag=wx.ALIGN_CENTER_VERTICAL | wx.RIGHT,
            border=5,
        )
        hboxAction.Add(actionDropdown, proportion=0, flag=wx.RIGHT, border=5)
        hboxAction.Add(colon, proportion=0, flag=wx.RIGHT, border=2)
        hboxAction.Add(valueTextCtrl, proportion=0, flag=wx.EXPAND)

        self.flexDebuggerSizer.Add(hboxBp, 0, wx.EXPAND)
        self.flexDebuggerSizer.Add(hboxAction, 0, wx.EXPAND)

        return addrTypeDropdown, addrTextCtrl, actionDropdown, valueTextCtrl

    def OnCollapsiblePaneChanged(self, event):
        self.Layout()
        if event:
            event.Skip()

    def OnCurrentDirCheckboxClick(self, event):
        self.curDir = self.runFromCurrentDirCheckbox.GetValue()

    def OnManualExecCheckboxClick(self, event):
        self.manualExecution = self.manualExecutionCheckbox.GetValue()
        self.curDir = True

    def OnEnforceTimeoutCheckboxClick(self, event):
        self.enforceTimeout = self.enforceTimeoutCheckbox.GetValue()

    def OnAnalyzerComplete(self, event):
        from CAPEsolo.analyzer import (
            Files,
            INJECT_LIST,
            disconnect_pipes,
            disconnect_logger,
            traceback,
            upload_files,
        )

        files = Files()
        files.dump_files()
        upload_files("debugger")
        upload_files("tlsdump")
        self.timer.Stop()
        self.log("Shutting down")
        try:
            if hasattr(self.analyzer, "command_pipe"):
                self.analyzer.command_pipe.stop()
            else:
                self.log("Analyzer object has no attribute 'command_pipe'")
            self.analyzer.log_pipe_server.stop()
            disconnect_pipes()
            disconnect_logger()
            for pid in INJECT_LIST:
                self.log(f"Monitor injection attempted but failed for process {pid}")
            self.log("Run completed")
            self.resultserver.shutdown_server()
        except Exception:
            self.log(traceback.format_exc())
        return True

    def MoveFiles(self, folder):
        logFolder = f"{self.analyzer.PATHS['root']}\\{folder}"
        try:
            if os.path.exists(logFolder):
                self.log(f"Uploading files at path {logFolder}")
            else:
                self.log(f"Folder at path {logFolder} does not exist, skipping")
                return
        except IOError as e:
            self.log(f"Unable to access folder at path {logFolder}: {e}")
            return

        for root, dirs, files in os.walk(logFolder):
            for file in files:
                file_path = os.path.join(root, file)
                analysis_path = os.path.join(folder, file)
                try:
                    # move files to analysis_path
                    shutil.move(file_path, analysis_path)
                except Exception as e:
                    self.log(f"Unable to copy file at path {file_path}: {e}")
        return

    def LoadAnalysisConfFile(self):
        try:
            analysisConf = os.path.join(self.capesoloRoot, "analysis_conf.default")
            with open(analysisConf, "r") as hfile:
                self.analysisEditor.SetValue(hfile.read())
        except IOError as e:
            wx.MessageBox(
                f"Failed to load analysis.conf: {str(e)}",
                "Error",
                wx.OK | wx.ICON_ERROR,
            )

    def OnOptionInputClick(self, event):
        if self.optionsCtrl.GetValue() == "option1=value, option2=value, etc...":
            self.optionsCtrl.SetValue("")
        event.Skip()

    def OnOptionInputFocus(self, event):
        if self.optionsCtrl.GetValue() == "":
            self.optionsCtrl.SetValue("option1=value, option2=value, etc...")
        event.Skip()

    def IdentifyPackage(self):
        package = ""
        f = SflockFile.from_path(str(self.target).encode("utf-8"))
        try:
            tmp_package = sflock_identify(f, check_shellcode=True)
        except Exception as e:
            log.error(f"Failed to sflock_ident due to {e}")
            tmp_package = ""

        if tmp_package and tmp_package in SANDBOXPACKAGES:
            if tmp_package in ("iso", "udf", "vhd"):
                package = "archive"
            else:
                package = tmp_package

        return package

    def PackageDropdown(self):
        directory = "modules\\packages"
        try:
            self.packageDropdown.Append("Auto-detect")
            for name in os.listdir(directory):
                if "init" not in name:
                    self.packageDropdown.Append(name.split(".")[0])
        except OSError as e:
            wx.LogError(f"Error accessing directory '{directory}': {e}")

    def OnTargetSelection(self):
        selection = self.targetPath.GetValue()
        self.target = Path(selection)

        if self.target.exists() and self.target.is_file():
            self.launchAnalyzerBtn.Enable()
        else:
            self.launchAnalyzerBtn.Disable()
            wx.MessageBox(
                f"The file {self.target} does not exist.",
                "Error",
                wx.OK | wx.ICON_ERROR,
            )

    def OnBrowse(self, event):
        initialDir = (
            Path(self.targetPath.GetValue()).parent
            if self.targetPath.GetValue()
            else "."
        )
        with wx.FileDialog(
            self,
            "Choose a file",
            wildcard="*.*",
            style=wx.FD_OPEN | wx.FD_FILE_MUST_EXIST | wx.FD_NO_FOLLOW,
            defaultDir=str(initialDir),
        ) as fileDialog:
            if fileDialog.ShowModal() == wx.ID_CANCEL:
                return

            pathname = fileDialog.GetPath()
            try:
                self.targetPath.SetValue(pathname)
                self.OnTargetSelection()
            except IOError:
                wx.LogError(f"Cannot open file '{pathname}'.")

    def CopyTarget(self):
        self.targetFile = (
            Path(self.analysisDir) / f"s_{hash_file(hashlib.sha256, self.target)}"
        )
        shutil.copy(self.target, self.targetFile)

    def StartAnalysis(self):
        from CAPEsolo.analyzer import (
            Analyzer,
            CuckooError,
            traceback,
        )

        self.CopyTarget()
        self.parent.targetFile = self.targetFile

        self.analyzer = None
        try:
            self.resultserver = ResultServer("localhost", 9999, self.analysisDir)
            self.analyzer = Analyzer()
            self.analyzer.prepare()
            mainFrame = self.GetMainFrame()
            size = mainFrame.GetSize()
            position = mainFrame.GetPosition()
            timerWindow = CountdownTimer(self, self.countdown, position, size)
            timerWindow.Show()
            self.StartAnalyzerThread(self.analyzer)
            self.terminateAnalyzerBtn.Enable()
            # os.unlink(ANALYSIS_CONF)

        except CuckooError:
            self.log("You probably submitted the job with wrong package")

        except Exception as e:
            error_exc = traceback.format_exc()
            error = str(e)
            self.log(f"{error} - {error_exc}\n")

    def AddTargetOptions(self, event):
        currentDatetime = datetime.now()
        formattedDatetime = currentDatetime.strftime("%Y%m%dT%H:%M:%S")
        filename = str(self.target)
        conf = self.analysisEditor.GetValue()
        userOptions = self.optionsCtrl.GetValue()
        sep = ","
        if userOptions == "option1=value, option2=value, etc...":
            userOptions = ""
            sep = ""
        if self.manualExecution:
            userOptions += f"{sep}manual=True, interactive=True"
            sep = ","
        if self.curDir:
            curdir = Path(filename).parent
            userOptions += f"{sep}curdir={curdir}"
        conf += f"\nenforce_timeout = {self.enforceTimeout}"
        self.countdown = int(self.timeoutInput.GetValue())
        conf += f"\ntimeout = {self.timeoutInput.GetValue()}"
        debuggerOptions = self.GetDebuggerOptions()
        conf += f"\nfile_name = {filename}"
        conf += f"\nclock = {formattedDatetime}"
        conf += f"\npackage = {self.package}"
        conf += f"\noptions = {userOptions},{debuggerOptions}"
        self.analysisEditor.SetValue(conf)

    def GetDebuggerOptions(self):
        opts = []
        for i in range(4):
            optstring = ""
            addrType = getattr(self, f"addrType{i}").GetValue()
            addr = getattr(self, f"addr{i}").GetValue()
            action = getattr(self, f"action{i}").GetValue()
            value = getattr(self, f"value{i}").GetValue()
            if addr:
                optstring = f"bp{i}=0x{addr}"
                if action:
                    optstring += f",action{i}={action}"
                    if value:
                        optstring += f":{value}"
                if addrType == "VA":
                    optstring += f",bpva{i}=1"
            if optstring:
                opts.append(optstring)
        if self.debugCount.GetValue():
            opts.append(f"count={self.debugCount.GetValue()}")
        if self.debugDepth.GetValue():
            opts.append(f"depth={self.debugDepth.GetValue()}")
        if self.baseApi.GetValue():
            opts.append(f"base-on-api={self.baseApi.GetValue()}")
        if self.apiList.GetValue():
            opts.append(f"break-on-return={self.apiList.GetValue()}")

        return ",".join(opts)

    def OnTerminateAnalyzer(self, event):
        try:
            idHash = "2b42b81577ab55cd2bcf2ac87b889bbb"
            completeFolder = os.path.join(os.environ["TMP"], idHash)
            Path(completeFolder).mkdir(exist_ok=True)
            self.terminateAnalyzerBtn.Disable()
        except Exception as e:
            wx.MessageBox(
                f"Could not terminate analyzer: {e}", "Error", wx.OK | wx.ICON_ERROR
            )

    def OnLaunchAnalyzer(self, event):
        try:
            self.package = self.packageDropdown.GetValue()
            if self.package == "Auto-detect":
                package = self.IdentifyPackage()
                if package:
                    self.package = package
                else:
                    wx.MessageBox(
                        f"Package identification error, select package manually.",
                        "Error",
                        wx.OK | wx.ICON_ERROR,
                    )
                    return

            originalPath = Path(self.targetPath.GetValue())
            newFilename = sanitize_filename(originalPath.name)
            if newFilename != originalPath.name:
                self.target = Path(originalPath.parent, newFilename)
                originalPath.rename(self.target)

            self.AddTargetOptions(event)
            self.SaveAnalysisFile(event, False)
            mainFrame = self.GetMainFrame()
            size = mainFrame.GetSize()
            position = mainFrame.GetPosition()
            loggerWindow = LoggerWindow(self, "Analysis Log", position, size)
            loggerWindow.Show()
            self.StartAnalysis()

        except Exception as e:
            wx.MessageBox(
                f"Failed to execute the command: {e}", "Error", wx.OK | wx.ICON_ERROR
            )

    def SaveAnalysisFile(self, event, ack=True):
        content = self.analysisEditor.GetValue()
        path = os.path.join("analysis.conf")
        try:
            with open(path, "w") as hfile:
                hfile.write(content)
            if ack:
                wx.MessageBox(
                    "analysis.conf saved successfully.",
                    "Success",
                    wx.OK | wx.ICON_INFORMATION,
                )
        except IOError as e:
            wx.MessageBox(
                f"Failed to save analysis.conf: {str(e)}",
                "Error",
                wx.OK | wx.ICON_ERROR,
            )

    def GetMainFrame(self):
        parent = self.GetParent()
        while parent and not isinstance(parent, wx.Frame):
            parent = parent.GetParent()
        return parent

    def log(self, message):
        log.info(message)

    def RunAnalyzer(self, analyzer, callback=None):
        result = analyzer.run()
        if callback:
            wx.CallAfter(callback, result)

    def StartAnalyzerThread(self, analyzer):
        def OnComplete(result):
            if result:
                evt = AnalyzerCompleteEvent(
                    EVT_ANALYZER_COMPLETE_ID, -1, "Analyzer completed"
                )
                wx.PostEvent(self, evt)

        Thread(target=self.RunAnalyzer, args=(analyzer, OnComplete)).start()

    def OnOpenDirectory(self, event):
        os.startfile(self.analysisDir)
