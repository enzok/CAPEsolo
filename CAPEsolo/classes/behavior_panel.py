import textwrap
from pathlib import Path

import wx
import wx.grid as gridlib

from .key_event import KeyEventHandlerMixin
from CAPEsolo.capelib.behavior import BehaviorAnalysis
from CAPEsolo.capelib.utils import convert_to_printable


class Options:
    def __init__(self):
        self.analysis_call_limit = None
        self.ram_boost = None


class BehaviorPanel(wx.Panel, KeyEventHandlerMixin):
    def __init__(self, parent):
        super(BehaviorPanel, self).__init__(parent)
        self.analysisDir = parent.analysisDir
        self.BindKeyEvents()
        self.behaviorComplete = False
        self.InitUI()

    def InitUI(self):
        vbox = wx.BoxSizer(wx.VERTICAL)

        vbox.AddSpacer(10)
        self.behaviorButton = wx.Button(self, label="Generate Behavior Results")
        self.behaviorButton.Bind(wx.EVT_BUTTON, self.GenerateBehavior)
        self.behaviorButton.Disable()
        vbox.Add(self.behaviorButton, proportion=0, border=5)

        self.hbox = wx.BoxSizer(wx.HORIZONTAL)
        self.categoryDropdown = wx.ComboBox(self, style=wx.CB_READONLY)
        self.hbox.Add(
            self.categoryDropdown, proportion=1, flag=wx.EXPAND | wx.RIGHT, border=5
        )
        self.viewButton = wx.Button(self, label="View")
        self.viewButton.Bind(wx.EVT_BUTTON, self.OnCatViewButton)
        self.hbox.Add(self.viewButton, proportion=0)
        vbox.Add(
            wx.StaticText(self, label="Categories:"), flag=wx.LEFT | wx.TOP, border=5
        )
        vbox.Add(self.hbox, flag=wx.EXPAND | wx.LEFT | wx.RIGHT | wx.BOTTOM, border=5)
        self.hbox2 = wx.BoxSizer(wx.HORIZONTAL)
        self.processDropdown = wx.ComboBox(self, style=wx.CB_READONLY)
        self.hbox2.Add(
            self.processDropdown, proportion=1, flag=wx.EXPAND | wx.RIGHT, border=5
        )
        self.viewProcButton = wx.Button(self, label="View")
        self.viewProcButton.Bind(wx.EVT_BUTTON, self.OnProcViewButton)
        self.hbox2.Add(self.viewProcButton, proportion=0)
        vbox.Add(
            wx.StaticText(self, label="Processes:"), flag=wx.LEFT | wx.TOP, border=5
        )
        vbox.Add(self.hbox2, flag=wx.EXPAND | wx.LEFT | wx.RIGHT | wx.BOTTOM, border=5)

        self.resultsWindow = wx.TextCtrl(self, style=wx.TE_MULTILINE | wx.TE_READONLY)
        vbox.Add(
            self.resultsWindow,
            proportion=1,
            flag=wx.EXPAND | wx.LEFT | wx.RIGHT | wx.BOTTOM,
            border=5,
        )
        vbox.Add(wx.StaticText(self, label="Calls:"), flag=wx.LEFT | wx.TOP, border=5)
        self.grid = gridlib.Grid(self)
        self.grid.CreateGrid(0, 8)
        columnLabels = [
            "Time",
            "TID",
            "Caller",
            "API",
            "Arguments",
            "Status",
            "Return",
            "Repeated",
        ]
        for i, label in enumerate(columnLabels):
            self.grid.SetColLabelValue(i, label)
            self.grid.SetColLabelAlignment(wx.ALIGN_CENTRE, wx.ALIGN_CENTRE)

        for col in range(self.grid.GetNumberCols()):
            attr = gridlib.GridCellAttr()
            attr.SetAlignment(wx.ALIGN_CENTRE, wx.ALIGN_CENTRE)
            self.grid.SetColAttr(col, attr)

        self.grid.SetColAttr(4, attr.SetAlignment(wx.ALIGN_LEFT, wx.ALIGN_CENTRE))
        self.grid.SetColAttr(8, attr.SetAlignment(wx.ALIGN_CENTRE, wx.ALIGN_CENTRE))
        self.grid.SetRowLabelSize(0)
        self.grid.EnableEditing(False)

        self.grid.Hide()
        vbox.Add(
            self.grid,
            proportion=1,
            flag=wx.EXPAND | wx.LEFT | wx.RIGHT | wx.BOTTOM,
            border=5,
        )

        self.SetSizer(vbox)

    def UpdateGenerateButtonState(self):
        logs_dir = Path(self.analysisDir) / "logs"
        if logs_dir.exists() and any(logs_dir.iterdir()) and not self.behaviorComplete:
            self.behaviorButton.Enable()
        else:
            self.behaviorButton.Disable()

    def GenerateBehavior(self, event):
        options = Options()
        options.analysis_call_limit = 0
        options.ram_boost = True
        behavior = BehaviorAnalysis()
        behavior.set_path(self.analysisDir)
        behavior.set_options(options)
        self.results = behavior.run()
        self.LoadResultCategories()
        self.LoadResultProcesses()
        self.behaviorButton.Disable()
        self.behaviorComplete = True

    def LoadResultProcesses(self):
        processes = self.results["processes"]
        self.processDropdown.Append("<Select process>")
        self.processDropdown.SetSelection(0)
        for process in processes:
            proc = (
                f'{process.get("process_id", "")}:{process.get("process_name", None)}'
            )
            self.processDropdown.Append(proc)

    def LoadResultCategories(self):
        categories = self.results.keys()
        self.categoryDropdown.Append("<Select category>")
        self.categoryDropdown.SetSelection(0)
        for category in categories:
            if "processes" not in category:
                self.categoryDropdown.Append(category)

    def OnCatViewButton(self, event):
        selectedCategory = self.categoryDropdown.GetValue()
        if not selectedCategory or selectedCategory == "<Select process>":
            wx.MessageBox(
                'Please select a category dropdown before clicking "View".',
                "No Category Selected",
                wx.OK | wx.ICON_WARNING,
            )
            return
        results = self.GetCatBehavior(selectedCategory)
        self.Display(results, selectedCategory)
        if isinstance(self.GetParent(), wx.Frame):
            self.GetParent().Fit()
            self.GetParent().Layout()

    def OnProcViewButton(self, event):
        selectedProcess = self.processDropdown.GetValue()
        if not selectedProcess or selectedProcess == "<Select process>":
            wx.MessageBox(
                'Please select a process dropdown before clicking "View".',
                "No Process Selected",
                wx.OK | wx.ICON_WARNING,
            )
            return
        results = self.GetProcBehavior(selectedProcess)
        self.Display(results, "process")

    def GetCatBehavior(self, category):
        results = self.results[category] or "No results"
        return results

    def GetProcBehavior(self, process):
        pid = process.split(":")[0]
        for proc in self.results.get("processes", []):
            if int(pid) == proc.get("process_id"):
                return proc

    def ViewData(self, data, indent=0, depth_limit=10):
        lines = []
        prefix = " " * indent

        if depth_limit <= 0:
            lines.append(f"{prefix}...")
            return "\n".join(lines)

        if isinstance(data, dict):
            for key, value in data.items():
                lines.append(f"{prefix}{key}:")
                lines.extend(
                    self.ViewData(value, indent + 4, depth_limit - 1).splitlines()
                )
        elif isinstance(data, list):
            for item in data:
                lines.extend(
                    self.ViewData(item, indent + 4, depth_limit - 1).splitlines()
                )
        elif isinstance(data, bytes):
            try:
                decoded = data.decode("utf-8")
                lines.append(f"{prefix}Binary String: '{decoded}'")
            except UnicodeDecodeError:
                lines.append(f"{prefix}Binary String: <binary data>")
        else:
            lines.append(f"{prefix}{data}")

        return "\n".join(lines)

    def GetArguments(self, data):
        args = []
        argsdata = data.get("arguments", [])
        for arg in argsdata:
            raw = arg.get("value")
            if isinstance(raw, str):
                if len(raw) > 64:
                    raw = "\n".join(
                        textwrap.wrap(
                            raw,
                            width=64,
                            break_long_words=True,
                            replace_whitespace=False,
                        )
                    )
            args.append(f' {arg.get("name")}: {raw}')
        return args

    def Display(self, data, dataType):
        if dataType == "process":
            height = 5 * self.resultsWindow.GetCharHeight()
            self.resultsWindow.SetSizeHints(-1, -1, -1, height)
            self.resultsWindow.SetMinSize((1, height))
            self.grid.Show()
            self.Layout()
            self.ViewProcess(data)
            self.ApplyAlternateRowShading()
        elif dataType == "processtree":
            height = 15 * self.resultsWindow.GetCharHeight()
            self.resultsWindow.SetSizeHints(-1, -1, -1, height)
            self.ViewProcessTree(data)
        else:
            height = 15 * self.resultsWindow.GetCharHeight()
            self.resultsWindow.SetSizeHints(-1, -1, -1, height)
            self.resultsWindow.SetValue(self.ViewData(data))

    def GetCmdLine(self, cmdline, modulepath):
        if cmdline.startswith('"'):
            splitcmdline = cmdline[cmdline[1:].index('"') + 2 :].split()
            argv0 = cmdline[: cmdline[1:].index('"') + 1].lower()
            if modulepath.lower() in argv0:
                cmdline = " ".join(splitcmdline).strip()
        elif cmdline:
            splitcmdline = cmdline.split()
            if splitcmdline:
                argv0 = splitcmdline[0].lower()
                if modulepath.lower() in argv0:
                    cmdline = " ".join(splitcmdline[1:]).strip()
        if len(cmdline) >= 200 + 15:
            cmdline = cmdline[:200] + " ...(truncated)"

        return convert_to_printable(cmdline)

    def PrintProcessTree(self, processes, indent=0):
        process_info = ""
        for process in processes:
            modulepath = process.get("module_path", "")
            cmdline = process.get("environ", {}).get("CommandLine", "")
            if cmdline:
                cmdline = self.GetCmdLine(cmdline, modulepath)
            process_info += f'{" " * indent}\u2022 {process.get("name")} {process.get("pid")} {cmdline}\n'
            for child in process.get("children", []):
                process_info += self.PrintProcessTree([child], indent + 4)

        return process_info

    def ViewProcessTree(self, data):
        output = self.PrintProcessTree(data)
        self.resultsWindow.SetValue(output)

    def ViewProcess(self, data):
        output = [
            f'Process Id: {data.get("process_id")}',
            f'Process Name: {data.get("process_name")}',
            f'Parent Id: {data.get("parent_id")}',
            f'Module Path: {data.get("module_path")}',
        ]
        self.resultsWindow.SetValue("\n".join(output))
        mycalls = []
        try:
            for _, call in enumerate(data.get("calls", [])):
                mycalls.append(call)
        except Exception:
            return

        self.AddTableData(mycalls)

    def AddTableData(self, apicalls):
        self.grid.AppendRows(len(apicalls))
        for i, call in enumerate(apicalls):
            self.grid.SetCellValue(i, 0, call.get("timestamp", ""))
            self.grid.SetCellValue(i, 1, str(call.get("thread_id", "")))

            caller = f'{call.get("parentcaller", "")}\n{call.get("caller", "")}'
            self.grid.SetCellValue(i, 2, caller)

            self.grid.SetCellValue(i, 3, call.get("api", ""))

            args = self.GetArguments(call)
            arguments_str = "\n".join(args)
            self.grid.SetCellValue(i, 4, arguments_str)

            status = "Success" if call.get("status", "") else "Failure"
            self.grid.SetCellValue(i, 5, status)

            return_val = str(call.get("return", ""))
            if call.get("pretty_return", ""):
                return_val = call.get("pretty_return")

            self.grid.SetCellValue(i, 6, return_val)
            self.grid.SetCellValue(i, 7, str(call.get("repeated", "")))

        self.grid.AutoSizeColumns()
        self.grid.AutoSizeRows()

    def ApplyAlternateRowShading(self):
        numRows = self.grid.GetNumberRows()
        lightGrey = wx.Colour(240, 240, 240)

        for row in range(numRows):
            if row % 2 == 0:
                attr = gridlib.GridCellAttr()
                attr.SetBackgroundColour(lightGrey)
                self.grid.SetRowAttr(row, attr)
        self.grid.ForceRefresh()
