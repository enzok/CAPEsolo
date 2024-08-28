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

log = logging.getLogger(__name__)

sandbox_packages = [
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
        self.analysisDir = parent.analysisDir
        self.analysisLogPath = os.path.join(parent.analysisDir, "analysis.log")
        self.debug = parent.debug
        self.package = ""
        self.capesoloRoot = parent.capesoloRoot
        self.targetFile = GetPreviousTarget(self.analysisDir)
        self.parent.targetFile = self.targetFile
        self.InitUi()
        self.LoadAnalysisConfFile()
        self.Bind(EVT_ANALYZER_COMPLETE, self.OnAnalyzerComplete)

    def InitUi(self):
        vbox = wx.BoxSizer(wx.VERTICAL)

        # File Dropdown and Browse Button
        hbox1 = wx.BoxSizer(wx.HORIZONTAL)
        self.targetPath = wx.TextCtrl(self)
        self.targetPath.SetValue("<Target file>")
        browse_btn = wx.Button(self, label="Browse...")
        browse_btn.Bind(wx.EVT_BUTTON, self.OnBrowse)
        hbox1.Add(self.targetPath, proportion=1, flag=wx.EXPAND | wx.RIGHT, border=5)
        hbox1.Add(browse_btn, proportion=0)

        hbox2 = wx.BoxSizer(wx.HORIZONTAL)
        packageLabel = wx.StaticText(self, label="Packages")
        self.packageDropdown = wx.ComboBox(self, style=wx.CB_READONLY)
        self.PackageDropdown()
        self.packageDropdown.SetValue("Auto-detect")
        self.runFromCurrentDirCheckbox = wx.CheckBox(
            self, label="Run sample from current directory"
        )
        self.runFromCurrentDirCheckbox.Bind(wx.EVT_CHECKBOX, self.OnCurrentDirCheckboxClick)
        self.runFromCurrentDirCheckbox.SetValue(True)
        self.manualExecutionCheckbox = wx.CheckBox(self, label="Manual Execution")
        self.manualExecutionCheckbox.Bind(wx.EVT_CHECKBOX, self.OnManualExecCheckboxClick)
        self.manualExecutionCheckbox.SetValue(False)
        hbox2.Add(packageLabel, flag=wx.RIGHT | wx.ALIGN_CENTER_VERTICAL, border=10)
        hbox2.Add(
            self.packageDropdown, proportion=0, flag=wx.EXPAND | wx.RIGHT, border=10
        )
        hbox2.Add(self.runFromCurrentDirCheckbox, flag=wx.ALIGN_CENTER_VERTICAL)
        hbox2.Add(self.manualExecutionCheckbox, flag=wx.ALIGN_CENTER_VERTICAL)

        # Optional Arguments Input
        hbox3 = wx.BoxSizer(wx.HORIZONTAL)
        args_label = wx.StaticText(self, label="Options")
        self.optionsCtrl = wx.TextCtrl(
            self,
            value="option1=value, option2=value, etc...",
            style=wx.TE_PROCESS_ENTER,
        )
        self.optionsCtrl.Bind(wx.EVT_LEFT_DOWN, self.OnOptionInputClick)
        self.optionsCtrl.Bind(wx.EVT_KILL_FOCUS, self.OnOptionInputFocus)
        hbox3.Add(args_label, flag=wx.RIGHT, border=5)
        hbox3.Add(self.optionsCtrl, proportion=1, flag=wx.EXPAND)

        # analysis.conf editor
        hbox4 = wx.BoxSizer(wx.HORIZONTAL)
        analysisConfLabel = wx.StaticText(self, label="analysis.conf")
        self.analysisEditor = wx.TextCtrl(self, style=wx.TE_MULTILINE, size=(-1, 100))
        hbox4.Add(
            self.analysisEditor, proportion=1, flag=wx.EXPAND | wx.RIGHT, border=5
        )

        hbox5 = wx.BoxSizer(wx.HORIZONTAL)
        self.launchAnalyzerBtn = wx.Button(self, label="Launch")
        self.launchAnalyzerBtn.Disable()
        self.launchAnalyzerBtn.Bind(wx.EVT_BUTTON, self.OnLaunchAnalyzer)
        self.terminateAnalyzerBtn = wx.Button(self, label="Kill")
        self.terminateAnalyzerBtn.Disable()
        self.terminateAnalyzerBtn.Bind(wx.EVT_BUTTON, self.OnTerminateAnalyzer)
        hbox5.Add(
            self.launchAnalyzerBtn, proportion=0, flag=wx.EXPAND | wx.RIGHT, border=5
        )
        hbox5.AddStretchSpacer(1)
        hbox5.Add(self.terminateAnalyzerBtn, proportion=0, flag=wx.EXPAND)
        self.terminateAnalyzerBtn.Disable()
        # Debugger window
        self.debugWindow = wx.TextCtrl(
            self, style=wx.TE_MULTILINE | wx.TE_READONLY | wx.EXPAND, size=(-1, 100)
        )

        # Layout
        vbox.Add(hbox1, flag=wx.EXPAND | wx.ALL, border=10)
        vbox.Add(hbox2, flag=wx.EXPAND | wx.LEFT | wx.RIGHT | wx.BOTTOM, border=10)
        vbox.Add(hbox3, flag=wx.EXPAND | wx.LEFT | wx.RIGHT | wx.BOTTOM, border=10)
        vbox.Add(analysisConfLabel, flag=wx.LEFT | wx.TOP, border=10)
        vbox.Add(
            hbox4,
            proportion=1,
            flag=wx.EXPAND | wx.LEFT | wx.RIGHT | wx.BOTTOM,
            border=10,
        )
        vbox.Add(hbox5, flag=wx.EXPAND | wx.LEFT | wx.RIGHT | wx.BOTTOM, border=10)

        if self.debug:
            vbox.Add(self.debugWindow, proportion=1, flag=wx.EXPAND | wx.ALL, border=10)
        else:
            self.debugWindow.Hide()

        self.SetSizer(vbox)

    def OnCurrentDirCheckboxClick(self, event):
        self.curDir = self.runFromCurrentDirCheckbox.GetValue()

    def OnManualExecCheckboxClick(self, event):
        self.manualExecution = self.manualExecutionCheckbox.GetValue()
        self.curDir = True

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
        log_folder = f"{self.analyzer.PATHS['root']}\\{folder}"
        try:
            if os.path.exists(log_folder):
                self.log(f"Uploading files at path {log_folder}")
            else:
                self.log(f"Folder at path {log_folder} does not exist, skipping")
                return
        except IOError as e:
            self.log(f"Unable to access folder at path {log_folder}: {e}")
            return

        for root, dirs, files in os.walk(log_folder):
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

        if tmp_package and tmp_package in sandbox_packages:
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
        current_datetime = datetime.now()
        formatted_datetime = current_datetime.strftime("%Y%m%dT%H:%M:%S")
        filename = str(self.target)
        conf = self.analysisEditor.GetValue()
        user_options = self.optionsCtrl.GetValue()
        sep = ","
        if user_options == "option1=value, option2=value, etc...":
            user_options = ""
            sep = ""
        if self.manualExecution:
            user_options += f"{sep}manual=True, interactive=True"
            sep = ","
        if self.curDir:
            curdir = Path(filename).parent
            user_options += f"{sep}curdir={curdir}"
        conf += f"\nfile_name = {filename}"
        conf += f"\nclock = {formatted_datetime}"
        conf += f"\npackage = {self.package}"
        conf += f"\noptions = {user_options}"
        self.analysisEditor.SetValue(conf)

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
            main_frame = self.GetMainFrame()
            size = main_frame.GetSize()
            position = main_frame.GetPosition()
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
        if self.debugWindow.IsShown():
            self.debugWindow.AppendText(message + "\n")

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
