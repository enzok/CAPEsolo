# Copyright (C) 2024 enzok
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

import argparse
import configparser
import importlib
import glob
import hashlib
import json
import logging
import os
import re
import shutil
import sys
import textwrap
import time
from contextlib import suppress
from datetime import datetime
from pathlib import Path
from threading import Thread

import wx
import wx.adv
import wx.grid as gridlib
import wx.lib.scrolledpanel as scrolled

CAPESOLO_ROOT = os.path.dirname(__file__)
sys.path.append(CAPESOLO_ROOT)
os.chdir(CAPESOLO_ROOT)

from capelib.cape_utils import (
    get_cape_name_from_yara_hit,
    get_cape_name_from_cape_type,
    metadata_processing,
)
from capelib.behavior import BehaviorAnalysis
from capelib.objects import File
from capelib.parse_pe import IsPEImage, PortableExecutable
from capelib.path_utils import path_mkdir
from capelib.resultserver import ResultServer
from capelib.utils import convert_to_printable
from capelib.yaralib import YaraProcessor
from lib.common.hashing import hash_file
from utils.update_parsers import update_parsers
from utils.update_yara import update_yara


log = logging.getLogger(__name__)
for handler in log.handlers[:]:
    log.removeHandler(handler)

EVT_ANALYZER_COMPLETE_ID = wx.NewIdRef()
EVT_ANALYZER_COMPLETE = wx.PyEventBinder(EVT_ANALYZER_COMPLETE_ID, 1)
TARGET_FILE = None
FONT_COURIER = None
ANALYSIS_CONF = os.path.join(CAPESOLO_ROOT, "analysis_conf")
ANALYSIS_CONF_DEFAULT = os.path.join(CAPESOLO_ROOT, "analysis_conf.default")
CONFIG_HITS = []
RESULTS = {}


def GetPreviousTarget(analysisDir):
    global TARGET_FILE
    for path in Path(analysisDir).glob("s_*"):
        if path.is_file():
            return path
    return None


def LoadFilesJson(analysisDir):
    filePath = Path(analysisDir) / "files.json"
    if filePath.exists():
        content = {}
        try:
            for line in open(filePath, "rb"):
                entry = json.loads(line)
                filePath = os.path.join(entry["path"])
                content[filePath] = {
                    "pids": entry.get("pids"),
                    "ppids": entry.get("ppids"),
                    "filepath": entry.get("filepath", ""),
                    "metadata": entry.get("metadata", {}),
                    "category": entry.get("category", ""),
                }
            return content
        except Exception as e:
            return {"error": "Corrupt analysis/files.json"}
    else:
        return {"error": "No dump files"}


class SplashScreen(wx.adv.SplashScreen):
    def __init__(self):
        bitmap = wx.Bitmap(os.path.join(CAPESOLO_ROOT, "capesolo.png"))
        super().__init__(
            bitmap,
            wx.adv.SPLASH_CENTRE_ON_SCREEN | wx.adv.SPLASH_TIMEOUT,
            2000,
            None,
            -1,
        )
        self.Bind(wx.EVT_CLOSE, self.OnClose)
        self.fc = wx.CallLater(1000, self.UpdateCountdown, 2)

    def OnClose(self, event):
        self.fc.Stop()
        event.Skip()

    def UpdateCountdown(self, count):
        if count > 0:
            self.fc.Restart(1000, self.UpdateCountdown, count - 1)
            print(f"{count}...")
        else:
            self.Close()


class KeyEventHandlerMixin:
    def BindKeyEvents(self):
        self.Bind(wx.EVT_CHAR_HOOK, self.OnKeyDown)

    def OnKeyDown(self, event):
        if event.GetKeyCode() == ord("F") and event.ControlDown():
            dlg = SearchDialog(self)
            dlg.ShowModal()
            dlg.Destroy()
        else:
            event.Skip()


class ProcessYara:
    def __init__(self, analysisDir):
        self.yara = YaraProcessor()
        self.yara.init_yara()
        self.yara_results = []
        self.analysisDir = analysisDir

    def Scan(self, target):
        hits = {}
        hits[target] = self.yara.get_yara(target)
        self.yara_results.append({target: hits[target]})

    def ScanDumps(self):
        hits = {}
        content = LoadFilesJson(self.analysisDir)
        if "error" not in content.keys():
            for file in content.keys():
                if content[file].get("category", "") in ("files", "CAPE", "procdump"):
                    path = os.path.join(self.analysisDir, file)
                    hits[file] = self.yara.get_yara(path)
                    self.yara_results.append({file: hits[file]})


class AnalyzerCompleteEvent(wx.PyCommandEvent):
    def __init__(self, etype, eid, message=None):
        super(AnalyzerCompleteEvent, self).__init__(etype, eid)
        self.message = message


class ConfigObject:
    def __init__(self, section_data):
        for key, value in section_data.items():
            setattr(self, key, value)


class ConfigReader:
    def __init__(self, config_file):
        self.config = configparser.ConfigParser()
        self.config.read(config_file)
        self._create_section_objects()

    def _create_section_objects(self):
        for section in self.config.sections():
            section_data = {
                key: self._to_boolean(value)
                for key, value in self.config.items(section)
            }
            setattr(self, section, ConfigObject(section_data))

    def _to_boolean(self, value):
        if isinstance(value, str):
            if value.lower() == "false":
                return False
            elif value.lower() == "true":
                return True
        return value


class CapesoloApp(wx.App):
    def OnInit(self):
        global FONT_COURIER
        FONT_COURIER = wx.Font(
            10, wx.FONTFAMILY_MODERN, wx.FONTSTYLE_NORMAL, wx.FONTWEIGHT_NORMAL
        )
        splash = SplashScreen()
        splash.Show()
        time.sleep(2)
        frame = MainFrame(None, size=(600, 800))
        frame.Show()
        return True


class Options:
    def __init__(self):
        self.analysis_call_limit = None
        self.ram_boost = None


class PayloadsPanel(wx.Panel):
    def __init__(self, parent):
        super(PayloadsPanel, self).__init__(parent)
        self.analysisDir = parent.analysisDir
        self.payloadsLoaded = False
        self.button_to_path = {}
        self.panel = scrolled.ScrolledPanel(self, -1)
        self.panel.SetupScrolling(scroll_x=True, scroll_y=True)
        self.panel.SetAutoLayout(1)
        self.panelsizer = wx.BoxSizer(wx.VERTICAL)
        self.panel.SetSizer(self.panelsizer)
        self.vbox = wx.BoxSizer(wx.VERTICAL)
        self.vbox.AddSpacer(10)
        self.vbox.Add(self.panel, 1, wx.EXPAND | wx.ALL, 10)
        self.SetSizer(self.vbox)

    def GridConf(self, grid):
        for col in range(grid.GetNumberCols()):
            attr = gridlib.GridCellAttr()
            attr.SetAlignment(wx.ALIGN_CENTRE, wx.ALIGN_CENTRE)
            grid.SetColAttr(col, attr)

        grid.SetColAttr(0, attr.SetAlignment(wx.ALIGN_LEFT, wx.ALIGN_CENTRE))
        grid.SetColAttr(1, attr.SetAlignment(wx.ALIGN_LEFT, wx.ALIGN_CENTRE))
        grid.EnableEditing(False)

    def AddNewRow(self, grid, value0, value1):
        current_row = grid.GetNumberRows()
        grid.AppendRows(1)
        grid.SetCellValue(current_row, 0, value0)
        grid.SetCellValue(current_row, 1, value1)

    def LoadAndDisplayContent(self):
        if self.payloadsLoaded:
            return
        data = LoadFilesJson(self.analysisDir)
        if "error" in data:
            return
        for key, value in data.items():
            if not key.startswith("aux_"):
                cape_info = {}
                metadata = data[key].get("metadata", "")
                if metadata:
                    cape_info = metadata_processing(metadata)
                path = Path(self.analysisDir) / key
                fileinfo = File(str(path)).get_all()[0]
                filepath = key[0].upper() + key[1:]

                grid = gridlib.Grid(self.panel)
                grid.CreateGrid(0, 2)
                grid.SetColLabelSize(0)
                grid.SetRowLabelSize(0)
                self.AddNewRow(grid, "Path", filepath)

                if "cape_type" in cape_info:
                    if cape_info.get("cape_type", ""):
                        self.AddNewRow(
                            grid, "CAPE Type", cape_info.get("cape_type", "N/A")
                        )

                if "cape_type_string" in cape_info:
                    cape_type = cape_info.get("cape_type_string", "N/A")
                    self.AddNewRow(grid, "CAPE Type", cape_type)
                    capename = get_cape_name_from_cape_type(cape_type)
                    CONFIG_HITS.append({filepath: capename})

                if "target_path" in cape_info:
                    self.AddNewRow(
                        grid, "Target Path", cape_info.get("target_path", "N/A")
                    )

                if "target_process" in cape_info:
                    self.AddNewRow(
                        grid, "Target Process", cape_info.get("target_process", "N/A")
                    )

                if "target_pid" in cape_info:
                    self.AddNewRow(
                        grid, "Target Pid", cape_info.get("target_pid", "N/A")
                    )

                if "virtual_address" in cape_info:
                    self.AddNewRow(
                        grid, "Virtual Address", cape_info.get("virtual_address", "N/A")
                    )

                if "pid" in cape_info:
                    self.AddNewRow(grid, "Pid", cape_info.get("pid", "N/A"))

                for key, value in fileinfo.items():
                    if key not in "path" and value:
                        value = str(value) + " bytes"
                        self.AddNewRow(grid, key[0].upper() + key[1:], value)

                grid.AutoSizeColumns()
                grid.SetColSize(0, 120)
                grid.AutoSizeRows()
                self.panelsizer.Add(
                    grid, proportion=0, flag=wx.EXPAND | wx.ALL, border=5
                )
                self.ApplyAlternateRowShading(grid)

                if IsPEImage(path.read_bytes()[:1024], 1024):
                    btn = wx.Button(self.panel, label="PE")
                    btn.Bind(wx.EVT_BUTTON, self.OnShowPe)
                    self.button_to_path[btn.GetId()] = path
                    self.panelsizer.Add(btn, 0, wx.ALIGN_LEFT | wx.ALL, 5)

                self.panelsizer.AddSpacer(5)

        self.panel.Layout()
        self.Layout()
        self.payloadsLoaded = True

    def ApplyAlternateRowShading(self, grid):
        numRows = grid.GetNumberRows()
        lightGrey = wx.Colour(240, 240, 240)

        for row in range(numRows):
            if row % 2 == 0:
                attr = gridlib.GridCellAttr()
                attr.SetBackgroundColour(lightGrey)
                grid.SetRowAttr(row, attr)
        grid.ForceRefresh()

    def GetMainFrame(self):
        parent = self.GetParent()
        while parent and not isinstance(parent, wx.Frame):
            parent = parent.GetParent()
        return parent

    def IsWindowOpen(self, title):
        for child in self.GetChildren():
            if isinstance(child, wx.Frame) and child.GetTitle() == title:
                return True
        return False

    def OnShowPe(self, event):
        try:
            main_frame = self.GetMainFrame()
            size = main_frame.GetSize()
            position = main_frame.GetPosition()
            buttonId = event.GetId()
            path = self.button_to_path.get(buttonId, "")
            if path and not self.IsWindowOpen(str(path)):
                viewer_window = PeWindow(self, str(path), path, position, size)
                viewer_window.Show()
        except Exception as e:
            wx.MessageBox(
                f"Failed to execute the command: {e}", "Error", wx.OK | wx.ICON_ERROR
            )


class YaraPanel(wx.Panel):
    def __init__(self, parent):
        super(YaraPanel, self).__init__(parent)
        self.yara = parent.yara
        self.analysisDir = parent.analysisDir
        self.yaraComplete = False
        self.filesjson = Path(self.analysisDir) / "files.json"
        self.InitUI()

    def InitUI(self):
        vbox = wx.BoxSizer(wx.VERTICAL)

        vbox.AddSpacer(10)
        self.yaraButton = wx.Button(self, label="Process Yara Results")
        self.yaraButton.Bind(wx.EVT_BUTTON, self.ProcessYara)
        self.yaraButton.Disable()
        vbox.Add(self.yaraButton, proportion=0, border=5)
        self.resultsWindow = wx.TextCtrl(
            self, style=wx.TE_MULTILINE | wx.TE_READONLY | wx.EXPAND, size=(-1, 100)
        )
        self.resultsWindow.SetFont(FONT_COURIER)
        vbox.Add(self.resultsWindow, proportion=1, flag=wx.EXPAND | wx.ALL, border=10)

        self.SetSizer(vbox)

    def PrintResults(self):
        global CONFIG_HITS
        yaras = self.yara.yara_results
        content = ""
        for filehits in yaras:
            paths = filehits.keys()
            for file in paths:
                content += f"\u2022 {file}:\n"
                for hit in filehits[file]:
                    capename = get_cape_name_from_yara_hit(hit)
                    if capename:
                        content += f"\tCAPE Name: {capename}\n"
                        CONFIG_HITS.append({file: capename})
                    content += f'\tName: {hit.get("name")}\n'
                    content += "\tStrings:\n"
                    for strval in hit.get("strings", []):
                        content += f"\t\t{strval}\n"
                    content += "\tAddresses:\n"
                    addrs = hit.get("addresses", {})
                    for key in addrs.keys():
                        content += f"\t\t{key}: {addrs[key]}\n"
        if not content:
            content = "No yara hits."

        return content

    def ProcessYara(self, event):
        try:
            self.yara.Scan(str(TARGET_FILE))
        except FileNotFoundError:
            print("Target not found. This may be normal.")
        self.yara.ScanDumps()
        content = self.PrintResults()
        self.resultsWindow.SetValue(content)
        self.yaraButton.Disable()
        self.yaraComplete = True

    def UpdateYaraButtonState(self):
        if not self.yaraComplete:
            self.yaraButton.Enable()
        else:
            self.yaraButton.Disable()


class ConfigsPanel(wx.Panel):
    def __init__(self, parent):
        super(ConfigsPanel, self).__init__(parent)
        self.analysisDir = parent.analysisDir
        self.configsComplete = False
        self.InitUI()

    def InitUI(self):
        vbox = wx.BoxSizer(wx.VERTICAL)

        vbox.AddSpacer(10)
        self.configsButton = wx.Button(self, label="Extract Configs")
        self.configsButton.Bind(wx.EVT_BUTTON, self.ExtractConfigs)
        self.configsButton.Disable()
        vbox.Add(self.configsButton, proportion=0, border=5)
        self.resultsWindow = wx.TextCtrl(
            self, style=wx.TE_MULTILINE | wx.TE_READONLY | wx.EXPAND, size=(-1, 100)
        )
        self.resultsWindow.SetFont(FONT_COURIER)
        vbox.Add(self.resultsWindow, proportion=1, flag=wx.EXPAND | wx.ALL, border=10)

        self.SetSizer(vbox)

    def PrintResults(self, cfg):
        content = ""
        if isinstance(cfg, list):
            for key, value in cfg[0].items():
                if isinstance(value, map):
                    value = list(value)
                content += f"\t{key}: {value}\n"
        elif isinstance(cfg, dict):
            for key, value in cfg.items():
                if isinstance(value, map):
                    value = list(value)
                content += f"\t{key}: {value}\n"
        return content

    def ExtractConfigs(self, event):
        content = ""
        for hit in CONFIG_HITS:
            decoderModule = ""
            hitPath = list(hit.keys())[0]
            hitName = hit.get(hitPath, "")
            path = os.path.join(CAPESOLO_ROOT, "parsers")
            decoders = [
                os.path.basename(decoder)[:-3]
                for decoder in glob.glob(f"{path}/[!_]*.py")
            ]
            for decoder in decoders:
                if hitName == decoder:
                    try:
                        decoderModule = importlib.import_module(
                            f"parsers.{decoder}", __package__
                        )
                        break
                    except Exception as e:
                        content += f"\n{path}: Fix parser code in {decoder}, {e}"
            if decoderModule:
                content = f"\u2022 {hitPath}:\n\tFamily: {hitName}\n"
                if self.analysisDir not in hitPath:
                    hitPath = Path(self.analysisDir) / hitPath
                filedata = Path(hitPath).read_bytes()
                if hasattr(decoderModule, "extract_config"):
                    cfg = decoderModule.extract_config(filedata)
                else:
                    cfg = decoderModule.config(filedata)
                content += self.PrintResults(cfg)
            else:
                content += f"\n{hitPath}: No parser for {hitName}"

        self.resultsWindow.SetValue(content)
        self.configsButton.Disable()
        self.configsComplete = True

    def UpdateConfigsButtonState(self):
        if CONFIG_HITS and not self.configsComplete:
            self.configsButton.Enable()
        else:
            self.configsButton.Disable()


class GridSearchDialog(wx.Dialog):
    def __init__(self, parent):
        super(GridSearchDialog, self).__init__(
            parent,
            title="Grid Search",
            size=(400, 100),
            style=wx.DEFAULT_DIALOG_STYLE | wx.STAY_ON_TOP,
        )
        self.grid = parent.grid
        self.InitUi()
        self.lastRow = 0
        self.lastCol = -1
        self.findWindow.Bind(wx.EVT_TEXT_ENTER, self.OnFind)
        self.Show()

    def InitUi(self):
        sizer = wx.BoxSizer(wx.VERTICAL)
        self.findWindow = wx.TextCtrl(self, style=wx.TE_PROCESS_ENTER)

        findButton = wx.Button(self, label="Find")
        findButton.Bind(wx.EVT_BUTTON, self.OnFind)
        findNextButton = wx.Button(self, label="Find Next")
        findNextButton.Bind(wx.EVT_BUTTON, self.OnFindNext)

        hbox1 = wx.BoxSizer(wx.HORIZONTAL)
        hbox1.Add(findButton, proportion=1, flag=wx.EXPAND | wx.RIGHT, border=5)
        hbox1.Add(findNextButton, proportion=1, flag=wx.EXPAND)

        sizer.Add(self.findWindow, proportion=0, flag=wx.EXPAND | wx.ALL, border=5)
        sizer.Add(hbox1, proportion=0, flag=wx.EXPAND | wx.ALL, border=5)

        self.SetSizer(sizer)
        self.Fit()

    def OnFind(self, event):
        self.lastRow = 0
        self.lastCol = -1
        self.Search(self.findWindow.GetValue(), False)

    def OnFindNext(self, event):
        self.Search(self.findWindow.GetValue())

    def Search(self, searchText, findNext=True):
        if searchText:
            rows = self.grid.GetNumberRows()
            cols = self.grid.GetNumberCols()
            start_row, start_col = (
                self.lastRow,
                self.lastCol + 1,
            )

            for row in range(start_row, rows):
                for col in range(start_col if row == start_row else 0, cols):
                    if searchText.lower() in self.grid.GetCellValue(row, col).lower():
                        self.grid.SetGridCursor(row, col)
                        self.grid.SelectBlock(row, col, row, col)
                        self.grid.MakeCellVisible(row, col)
                        self.grid.SetFocus()
                        self.grid.ForceRefresh()
                        self.lastRow, self.lastCol = (row, col)
                        return
                start_col = 0

            if findNext and (start_row != 0 or start_col != 0):
                self.lastRow, self.lastCol = 0, -1
                self.Search(searchText, findNext=False)
            else:
                wx.MessageBox(
                    "No more matches found.",
                    "Search Result",
                    wx.OK | wx.ICON_INFORMATION,
                )


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
        global RESULTS
        options = Options()
        options.analysis_call_limit = 0
        options.ram_boost = True
        behavior = BehaviorAnalysis()
        behavior.set_path(self.analysisDir)
        behavior.set_options(options)
        RESULTS = behavior.run()
        self.results = RESULTS
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


class WxTextCtrlHandler(logging.Handler):
    def __init__(self, textctrl):
        super(WxTextCtrlHandler, self).__init__()
        self.textctrl = textctrl

    def emit(self, record):
        msg = self.format(record)
        wx.CallAfter(self.textctrl.AppendText, msg + "\n")


class SearchDialog(wx.Dialog):
    def __init__(self, parent):
        super(SearchDialog, self).__init__(
            parent,
            title="Find",
            size=(400, 100),
            style=wx.DEFAULT_DIALOG_STYLE | wx.STAY_ON_TOP,
        )
        self.resultsWindow = parent.resultsWindow
        self.lastFoundPos = -1
        self.InitUi()
        self.findWindow.Bind(wx.EVT_TEXT_ENTER, self.OnFind)

    def InitUi(self):
        sizer = wx.BoxSizer(wx.VERTICAL)
        self.findWindow = wx.TextCtrl(self, style=wx.TE_PROCESS_ENTER)

        findButton = wx.Button(self, label="Find")
        findButton.Bind(wx.EVT_BUTTON, self.OnFind)
        findNextButton = wx.Button(self, label="Find Next")
        findNextButton.Bind(wx.EVT_BUTTON, self.OnFindNext)

        hbox1 = wx.BoxSizer(wx.HORIZONTAL)
        hbox1.Add(findButton, proportion=1, flag=wx.EXPAND | wx.RIGHT, border=5)
        hbox1.Add(findNextButton, proportion=1, flag=wx.EXPAND)

        sizer.Add(self.findWindow, proportion=0, flag=wx.EXPAND | wx.ALL, border=5)
        sizer.Add(hbox1, proportion=0, flag=wx.EXPAND | wx.ALL, border=5)

        self.SetSizer(sizer)
        self.Fit()

    def OnFind(self, event):
        self.FindText()

    def OnFindNext(self, event):
        self.FindText(startPos=self.lastFoundPos + 1)

    def FindText(self, startPos=0):
        searchText = self.findWindow.GetValue()
        content = self.resultsWindow.GetValue()
        self.lastFoundPos = content.find(searchText, startPos)
        self.HighlightText()

    def HighlightText(self):
        if self.lastFoundPos != -1:
            searchText = self.findWindow.GetValue()
            searchTextLength = len(searchText)
            textCtrl = self.resultsWindow
            backgroundColor = wx.SystemSettings.GetColour(wx.SYS_COLOUR_WINDOW)
            textCtrl.SetStyle(
                self.lastFoundPos,
                self.lastFoundPos + searchTextLength,
                wx.TextAttr("red", backgroundColor),
            )
            textCtrl.ShowPosition(self.lastFoundPos)
            wx.CallLater(
                5000,
                self.ResetHighlight,
                textCtrl,
                self.lastFoundPos,
                searchTextLength,
            )
            textCtrl.SetFocus()
        else:
            wx.MessageBox(
                "Text not found.", "Search Result", wx.OK | wx.ICON_INFORMATION
            )

    def ResetHighlight(self, textCtrl, start, length):
        textColor = wx.SystemSettings.GetColour(wx.SYS_COLOUR_WINDOWTEXT)
        backgroundColor = wx.SystemSettings.GetColour(wx.SYS_COLOUR_WINDOW)
        textCtrl.SetStyle(
            start,
            start + length,
            wx.TextAttr(textColor, backgroundColor),
        )
        textCtrl.Refresh()
        textCtrl.Update()

    def SetSelection(self, textCtrl, searchTextLength):
        textCtrl.SetSelection(self.lastFoundPos, self.lastFoundPos + searchTextLength)
        textCtrl.ShowPosition(self.lastFoundPos)
        textCtrl.Refresh()


class PeWindow(wx.Frame, KeyEventHandlerMixin):
    def __init__(
        self,
        parent,
        title,
        filepath,
        main_window_position,
        main_window_size,
        *args,
        **kwargs,
    ):
        super(PeWindow, self).__init__(parent, title=title, *args, **kwargs)
        self.data = PortableExecutable(str(filepath)).run()
        self.panel = scrolled.ScrolledPanel(self, -1)
        self.panel.SetAutoLayout(1)
        self.panel.SetupScrolling(scroll_x=True, scroll_y=True)
        self.vbox = wx.BoxSizer(wx.VERTICAL)
        self.BindKeyEvents()
        self.main_window_position = main_window_position
        self.main_window_size = main_window_size
        self.peInfos = [
            "imagebase",
            "entrypoint",
            "reported_checksum",
            "actual_checksum",
            "osversion",
            "timestamp",
            "imphash",
            "exported_dll_name",
            "pdbpath",
        ]
        self.InitUI()

    def InitUI(self):
        self.vbox.AddSpacer(10)
        data = self.UpdatePeData(self.data)
        self.CreateGrids(data)
        saveBtn = wx.Button(self.panel, label="Save PE Info")
        saveBtn.Bind(wx.EVT_BUTTON, self.OnSavePeInfo)
        self.vbox.Add(saveBtn, proportion=0, flag=wx.ALL | wx.LEFT, border=5)

        self.panel.SetSizer(self.vbox)
        self.main_window_position.x += self.main_window_size.x
        self.SetSize(self.main_window_size)
        self.SetPosition(self.main_window_position)

    def CreateGrids(self, data):
        keyLabels = {
            "peinfo": "PE Info",
            "versioninfo": "Version Info",
            "sections": "Sections",
            "imports": "Imports",
            "exports": "Exports",
            "resources": "Resources",
            "dirents": "Directory Entries",
        }
        for key in keyLabels.keys():
            value = data.get(key, "")
            if not value:
                continue

            gridTitle = wx.StaticText(self.panel, label=keyLabels[key])
            font = wx.Font(
                12, wx.FONTFAMILY_DEFAULT, wx.FONTSTYLE_NORMAL, wx.FONTWEIGHT_BOLD
            )
            gridTitle.SetFont(font)
            self.vbox.Add(gridTitle, 0, wx.EXPAND | wx.ALL, 5)
            populate_func = getattr(self, "Populate" + key.capitalize(), None)
            if callable(populate_func):
                populate_func(value)
                self.vbox.AddSpacer(5)

        self.panel.Layout()
        self.Layout()

    def UpdatePeData(self, data):
        newData = {}

        for key in self.peInfos:
            if key in data:
                newData[key] = data.pop(key)

        data["peinfo"] = newData
        return data

    def GridConf(self, grid):
        for col in range(grid.GetNumberCols()):
            attr = gridlib.GridCellAttr()
            attr.SetAlignment(wx.ALIGN_CENTRE, wx.ALIGN_CENTRE)
            grid.SetColAttr(col, attr)

        grid.SetColAttr(0, attr.SetAlignment(wx.ALIGN_LEFT, wx.ALIGN_CENTRE))
        grid.SetColAttr(1, attr.SetAlignment(wx.ALIGN_LEFT, wx.ALIGN_CENTRE))
        grid.EnableEditing(False)

    def PopulatePeinfo(self, peInfo):
        columnLabels = [
            "Image Base",
            "Entry Point",
            "Reported Checksum",
            "Actual Checksum",
            "Minimum OS Version",
            "Compile Time",
            "Import Hash",
            "Exported DLL Name",
            "PDB Path",
        ]

        grid = gridlib.Grid(self.panel)
        grid.CreateGrid(1, len(columnLabels))
        grid.SetRowLabelSize(0)

        for i, label in enumerate(columnLabels):
            grid.SetColLabelValue(i, label)
            grid.SetColLabelAlignment(wx.ALIGN_CENTRE, wx.ALIGN_CENTRE)

        self.GridConf(grid)

        for col, key in enumerate(peInfo):
            value = str(peInfo.get(key, ""))
            grid.SetCellValue(0, col, value)

        grid.AutoSizeColumns()
        grid.AutoSizeRows()

        self.vbox.Add(grid, proportion=0, flag=wx.EXPAND | wx.ALL, border=10)
        self.ApplyAlternateRowShading(grid)

    def PopulateVersioninfo(self, versionInfo):
        grid = gridlib.Grid(self.panel)
        grid.CreateGrid(0, 2)
        grid.SetRowLabelSize(0)
        grid.SetColLabelSize(0)

        self.GridConf(grid)

        for info in versionInfo:
            current_row = grid.GetNumberRows()
            grid.AppendRows(1)
            grid.SetCellValue(current_row, 0, info.get("name", ""))
            grid.SetCellValue(current_row, 1, info.get("value", ""))

        grid.AutoSizeColumns()
        grid.AutoSizeRows()

        self.vbox.Add(grid, proportion=0, flag=wx.EXPAND | wx.ALL, border=10)
        self.ApplyAlternateRowShading(grid)

    def PopulateSections(self, sectionData):
        sections = [
            "name",
            "raw_address",
            "virtual_address",
            "virtual_size",
            "size_of_data",
            "characteristics",
            "entropy",
        ]
        columnLabels = [
            "Name",
            "RAW Address",
            "Virtual Address",
            "Virtual Size",
            "Size of Raw Data",
            "Characteristics",
            "Entropy",
        ]

        grid = gridlib.Grid(self.panel)
        grid.CreateGrid(0, len(columnLabels))
        grid.SetRowLabelSize(0)

        for i, label in enumerate(columnLabels):
            grid.SetColLabelValue(i, label)
            grid.SetColLabelAlignment(wx.ALIGN_CENTRE, wx.ALIGN_CENTRE)

        self.GridConf(grid)

        for section in sectionData:
            current_row = grid.GetNumberRows()
            grid.AppendRows(1)
            col = 0
            for key in sections:
                value = section.get(key, "")
                grid.SetCellValue(current_row, col, value)
                col += 1

        grid.AutoSizeColumns()
        grid.AutoSizeRows()

        self.vbox.Add(grid, proportion=0, flag=wx.EXPAND | wx.ALL, border=10)
        self.ApplyAlternateRowShading(grid)

    def PopulateImports(self, importData):
        grid = gridlib.Grid(self.panel)
        grid.CreateGrid(0, 3)
        grid.SetRowLabelSize(0)

        grid.SetColLabelValue(0, "Module")
        grid.SetColLabelValue(1, "Name")
        grid.SetColLabelValue(2, "Address")
        grid.SetColLabelAlignment(wx.ALIGN_CENTRE, wx.ALIGN_CENTRE)

        self.GridConf(grid)

        for name, values in importData.items():
            imports = values.get("imports", [])
            for item in imports:
                current_row = grid.GetNumberRows()
                grid.AppendRows(1)
                grid.SetCellValue(current_row, 0, name)
                grid.SetCellValue(current_row, 1, item.get("name", ""))
                grid.SetCellValue(current_row, 2, item.get("address", ""))

        grid.AutoSizeColumns()
        grid.AutoSizeRows()

        self.vbox.Add(grid, proportion=0, flag=wx.EXPAND | wx.ALL, border=10)
        self.ApplyAlternateRowShading(grid)

    def PopulateResources(self, resourceData):
        resources = [
            "name",
            "offset",
            "size",
            "language",
            "sublanguage",
            "entropy",
            "filetype",
        ]
        columnLabels = [
            "Name",
            "Offset",
            "Size",
            "Language",
            "Sub-language",
            "Entropy",
            "File type",
        ]

        grid = gridlib.Grid(self.panel)
        grid.CreateGrid(0, len(columnLabels))
        grid.SetRowLabelSize(0)

        for i, label in enumerate(columnLabels):
            grid.SetColLabelValue(i, label)
            grid.SetColLabelAlignment(wx.ALIGN_CENTRE, wx.ALIGN_CENTRE)

        self.GridConf(grid)

        for section in resourceData:
            current_row = grid.GetNumberRows()
            grid.AppendRows(1)
            col = 0
            for key in resources:
                value = str(section.get(key, ""))
                grid.SetCellValue(current_row, col, value)
                col += 1

        grid.AutoSizeColumns()
        grid.AutoSizeRows()

        self.vbox.Add(grid, proportion=0, flag=wx.EXPAND | wx.ALL, border=10)
        self.ApplyAlternateRowShading(grid)

    def PopulateExports(self, exportData):
        grid = gridlib.Grid(self.panel)
        grid.CreateGrid(0, 3)
        grid.SetRowLabelSize(0)

        grid.SetColLabelValue(0, "Name")
        grid.SetColLabelValue(1, "Address")
        grid.SetColLabelValue(2, "Ordinal")
        grid.SetColLabelAlignment(wx.ALIGN_CENTRE, wx.ALIGN_CENTRE)

        self.GridConf(grid)

        for export in exportData:
            current_row = grid.GetNumberRows()
            grid.AppendRows(1)
            grid.SetCellValue(current_row, 0, export.get("name", ""))
            grid.SetCellValue(current_row, 1, export.get("address", ""))
            grid.SetCellValue(current_row, 2, str(export.get("ordinal", "")))

        grid.AutoSizeColumns()
        grid.AutoSizeRows()

        self.vbox.Add(grid, proportion=0, flag=wx.EXPAND | wx.ALL, border=10)
        self.ApplyAlternateRowShading(grid)

    def PopulateDirents(self, direntsData):
        grid = gridlib.Grid(self.panel)
        grid.CreateGrid(0, 3)
        grid.SetRowLabelSize(0)

        grid.SetColLabelValue(0, "Name")
        grid.SetColLabelValue(1, "Virtual Address")
        grid.SetColLabelValue(2, "Size")
        grid.SetColLabelAlignment(wx.ALIGN_CENTRE, wx.ALIGN_CENTRE)

        self.GridConf(grid)

        for ent in direntsData:
            current_row = grid.GetNumberRows()
            grid.AppendRows(1)
            grid.SetCellValue(current_row, 0, ent.get("name", ""))
            grid.SetCellValue(current_row, 1, ent.get("virtual_address", ""))
            grid.SetCellValue(current_row, 2, ent.get("size", ""))

        grid.AutoSizeColumns()
        grid.AutoSizeRows()

        self.vbox.Add(grid, proportion=0, flag=wx.EXPAND | wx.ALL, border=10)
        self.ApplyAlternateRowShading(grid)

    def ApplyAlternateRowShading(self, grid):
        numRows = grid.GetNumberRows()
        lightGrey = wx.Colour(240, 240, 240)

        for row in range(numRows):
            if row % 2 == 0:
                attr = gridlib.GridCellAttr()
                attr.SetBackgroundColour(lightGrey)
                grid.SetRowAttr(row, attr)
        grid.ForceRefresh()

    def OnSavePeInfo(self, event):
        with wx.FileDialog(
            self,
            "Save PE Info as...",
            wildcard="Text files (*.txt)|*.txt",
            style=wx.FD_SAVE | wx.FD_OVERWRITE_PROMPT,
        ) as fileDialog:
            if fileDialog.ShowModal() == wx.ID_CANCEL:
                return
            pathname = fileDialog.GetPath()
            try:
                with open(pathname, "w") as outfile:
                    json.dump(self.data, outfile, indent=4)
            except IOError:
                wx.LogError(f"Cannot save PE Info to file '{pathname}'.")


class LoggerWindow(wx.Frame, KeyEventHandlerMixin):
    def __init__(
        self, parent, title, main_window_position, main_window_size, *args, **kwargs
    ):
        super(LoggerWindow, self).__init__(parent, title=title, *args, **kwargs)
        self.BindKeyEvents()
        self.main_window_position = main_window_position
        self.main_window_size = main_window_size
        self.InitUI()

    def InitUI(self):
        panel = wx.Panel(self)
        vbox = wx.BoxSizer(wx.VERTICAL)

        self.resultsWindow = wx.TextCtrl(
            panel, style=wx.TE_MULTILINE | wx.TE_READONLY | wx.TE_RICH2
        )
        self.resultsWindow.SetFont(FONT_COURIER)
        vbox.Add(self.resultsWindow, proportion=1, flag=wx.EXPAND | wx.ALL, border=5)
        saveBtn = wx.Button(panel, label="Save Log")
        saveBtn.Bind(wx.EVT_BUTTON, self.OnSaveLog)
        vbox.Add(saveBtn, proportion=0, flag=wx.ALL | wx.CENTER, border=5)
        panel.SetSizer(vbox)

        handler = WxTextCtrlHandler(self.resultsWindow)
        logging.basicConfig(
            level=logging.DEBUG,
            handlers=[handler],
            format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
        )

        self.main_window_position.x += self.main_window_size.x
        self.SetSize(self.main_window_size)
        self.SetPosition(self.main_window_position)

    def OnSaveLog(self, event):
        with wx.FileDialog(
            self,
            "Save log as...",
            wildcard="Text files (*.txt)|*.txt",
            style=wx.FD_SAVE | wx.FD_OVERWRITE_PROMPT,
        ) as fileDialog:
            if fileDialog.ShowModal() == wx.ID_CANCEL:
                return
            pathname = fileDialog.GetPath()
            try:
                with open(pathname, "w") as file:
                    file.write(self.resultsWindow.GetValue())
            except IOError:
                wx.LogError(f"Cannot save log to file '{pathname}'.")


class TargetInfoPanel(wx.Panel):
    def __init__(self, parent):
        super(TargetInfoPanel, self).__init__(parent)
        self.infoLoaded = False
        self.peData = {}
        self.InitUI()

    def InitUI(self):
        vbox = wx.BoxSizer(wx.VERTICAL)
        vbox.AddSpacer(10)
        self.grid = gridlib.Grid(self)
        self.grid.CreateGrid(0, 2)
        self.grid.SetColLabelSize(0)
        self.grid.SetRowLabelSize(0)

        for col in range(self.grid.GetNumberCols()):
            attr = gridlib.GridCellAttr()
            attr.SetAlignment(wx.ALIGN_CENTRE, wx.ALIGN_CENTRE)
            self.grid.SetColAttr(col, attr)

        self.grid.SetColAttr(0, attr.SetAlignment(wx.ALIGN_LEFT, wx.ALIGN_CENTRE))
        self.grid.SetColAttr(1, attr.SetAlignment(wx.ALIGN_LEFT, wx.ALIGN_CENTRE))
        self.grid.EnableEditing(False)
        vbox.Add(self.grid, proportion=1, flag=wx.EXPAND | wx.ALL, border=5)
        self.peButton = wx.Button(self, label="PE")
        self.peButton.Bind(wx.EVT_BUTTON, self.OnShowPe)
        self.peButton.Hide()
        vbox.Add(self.peButton, proportion=0, flag=wx.LEFT, border=5)

        self.SetSizer(vbox)

    def AddNewRow(self, value0, value1):
        current_row = self.grid.GetNumberRows()
        self.grid.AppendRows(1)
        self.grid.SetCellValue(current_row, 0, value0)
        self.grid.SetCellValue(current_row, 1, value1)

    def LoadAndDisplayContent(self):
        if self.infoLoaded or not TARGET_FILE:
            return
        fileObj = File(str(TARGET_FILE))
        fileinfo = fileObj.get_all()[0]
        self.AddNewRow("Path", str(TARGET_FILE))
        for key, value in fileinfo.items():
            if key not in "path" and value:
                if not isinstance(value, str):
                    value = str(value) + " bytes"
                self.AddNewRow(key[0].upper() + key[1:], value)
        self.grid.AutoSizeColumns()
        self.grid.SetColSize(0, 120)
        self.grid.AutoSizeRows()
        self.ApplyAlternateRowShading()
        self.peButton.Show()
        self.Layout()
        self.infoLoaded = True

    def ApplyAlternateRowShading(self):
        numRows = self.grid.GetNumberRows()
        lightGrey = wx.Colour(240, 240, 240)

        for row in range(numRows):
            if row % 2 == 0:
                attr = gridlib.GridCellAttr()
                attr.SetBackgroundColour(lightGrey)
                self.grid.SetRowAttr(row, attr)
        self.grid.ForceRefresh()

    def OnShowPe(self, event):
        try:
            main_frame = self.GetMainFrame()
            size = main_frame.GetSize()
            position = main_frame.GetPosition()
            viewer_window = PeWindow(
                self, f"{str(TARGET_FILE)}", TARGET_FILE, position, size
            )
            viewer_window.Show()
        except Exception as e:
            wx.MessageBox(
                f"Failed to execute the command: {e}", "Error", wx.OK | wx.ICON_ERROR
            )

    def GetMainFrame(self):
        parent = self.GetParent()
        while parent and not isinstance(parent, wx.Frame):
            parent = parent.GetParent()
        return parent


class StartPanel(wx.Panel):
    def __init__(self, parent):
        global TARGET_FILE
        super().__init__(parent)
        self.curDir = True
        self.analysisDir = parent.analysisDir
        self.debug = parent.debug
        TARGET_FILE = GetPreviousTarget(self.analysisDir)
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
        package_label = wx.StaticText(self, label="Packages")
        self.packageDropdown = wx.ComboBox(self, style=wx.CB_READONLY)
        self.PackageDropdown()
        self.packageDropdown.SetValue("exe")
        self.runFromCurrentDirCheckbox = wx.CheckBox(
            self, label="Run sample from current directory"
        )
        self.runFromCurrentDirCheckbox.Bind(wx.EVT_CHECKBOX, self.OnCheckboxClick)
        hbox2.Add(package_label, flag=wx.RIGHT | wx.ALIGN_CENTER_VERTICAL, border=10)
        hbox2.Add(
            self.packageDropdown, proportion=0, flag=wx.EXPAND | wx.RIGHT, border=10
        )
        hbox2.Add(self.runFromCurrentDirCheckbox, flag=wx.ALIGN_CENTER_VERTICAL)

        # Optional Arguments Input
        hbox3 = wx.BoxSizer(wx.HORIZONTAL)
        args_label = wx.StaticText(self, label="Options")
        self.optionsCtrl = wx.TextCtrl(
            self,
            value="option1=value, option2=value, etc...",
            style=wx.TE_PROCESS_ENTER,
        )
        self.optionsCtrl.Bind(wx.EVT_LEFT_DOWN, self.OnOptionInputClick)
        self.optionsCtrl.Bind(wx.EVT_SET_FOCUS, self.OnOptionInputFocus)
        hbox3.Add(args_label, flag=wx.RIGHT, border=5)
        hbox3.Add(self.optionsCtrl, proportion=1, flag=wx.EXPAND)

        # analysis.conf editor
        hbox4 = wx.BoxSizer(wx.HORIZONTAL)
        analysis_conf_label = wx.StaticText(self, label="analysis.conf")
        self.analysisEditor = wx.TextCtrl(self, style=wx.TE_MULTILINE, size=(-1, 100))
        hbox4.Add(
            self.analysisEditor, proportion=1, flag=wx.EXPAND | wx.RIGHT, border=5
        )

        hbox5 = wx.BoxSizer(wx.HORIZONTAL)
        self.launch_analyzer_btn = wx.Button(self, label="Launch")
        self.launch_analyzer_btn.Disable()
        self.launch_analyzer_btn.Bind(wx.EVT_BUTTON, self.OnLaunchAnalyzer)
        hbox5.Add(
            self.launch_analyzer_btn, proportion=0, flag=wx.EXPAND | wx.RIGHT, border=5
        )

        # Debugger window
        self.debugWindow = wx.TextCtrl(
            self, style=wx.TE_MULTILINE | wx.TE_READONLY | wx.EXPAND, size=(-1, 100)
        )

        # Layout
        vbox.Add(hbox1, flag=wx.EXPAND | wx.ALL, border=10)
        vbox.Add(hbox2, flag=wx.EXPAND | wx.LEFT | wx.RIGHT | wx.BOTTOM, border=10)
        vbox.Add(hbox3, flag=wx.EXPAND | wx.LEFT | wx.RIGHT | wx.BOTTOM, border=10)
        vbox.Add(analysis_conf_label, flag=wx.LEFT | wx.TOP, border=10)
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

    def OnCheckboxClick(self, event):
        self.curDir = self.runFromCurrentDirCheckbox.GetValue()

    def OnAnalyzerComplete(self, event):
        from analyzer import (
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
            with open(ANALYSIS_CONF_DEFAULT, "r") as hfile:
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
        if self.optionsCtrl.GetValue() == "option1=value, option2=value, etc...":
            self.optionsCtrl.SetValue("")
        event.Skip()

    def PackageDropdown(self):
        directory = "modules\\packages"
        try:
            for name in os.listdir(directory):
                if "init" not in name:
                    self.packageDropdown.Append(name.split(".")[0])
        except OSError as e:
            wx.LogError(f"Error accessing directory '{directory}': {e}")

    def OnTargetSelection(self):
        selection = self.targetPath.GetValue()
        self.target = Path(selection)

        if self.target.exists() and self.target.is_file():
            self.launch_analyzer_btn.Enable()
        else:
            self.launch_analyzer_btn.Disable()
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
            style=wx.FD_OPEN | wx.FD_FILE_MUST_EXIST,
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
        global TARGET_FILE
        TARGET_FILE = (
            Path(self.analysisDir) / f"s_{hash_file(hashlib.sha256, self.target)}"
        )
        shutil.copy(self.target, TARGET_FILE)

    def StartAnalysis(self):
        from analyzer import (
            Analyzer,
            CuckooError,
            traceback,
        )

        self.CopyTarget()

        self.analyzer = None
        try:
            self.resultserver = ResultServer("localhost", 9999, self.analysisDir)
            self.analyzer = Analyzer()
            self.analyzer.prepare()
            self.StartAnalyzerThread(self.analyzer)
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
        filename = self.targetPath.GetValue()
        conf = self.analysisEditor.GetValue()
        package = self.packageDropdown.GetValue()
        self.OnOptionInputClick(event)
        user_options = self.optionsCtrl.GetValue()
        if self.curDir:
            curdir = Path(filename).parent
            user_options += f", curdir={curdir}"
        conf += f"\nfile_name = {filename}"
        conf += f"\nclock = {formatted_datetime}"
        conf += f"\npackage = {package}"
        conf += f"\noptions = {user_options}"
        self.analysisEditor.SetValue(conf)

    def OnLaunchAnalyzer(self, event):
        try:
            self.AddTargetOptions(event)
            self.SaveAnalysisFile(event, False)
            main_frame = self.GetMainFrame()
            size = main_frame.GetSize()
            position = main_frame.GetPosition()
            viewer_window = LoggerWindow(self, "Analysis Log", position, size)
            viewer_window.Show()
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


class StringsPanel(wx.Panel, KeyEventHandlerMixin):
    def __init__(self, parent):
        super(StringsPanel, self).__init__(parent)
        self.analysisDir = parent.analysisDir
        self.BindKeyEvents()
        self.InitUI()

    def InitUI(self):
        vbox = wx.BoxSizer(wx.VERTICAL)

        hbox = wx.BoxSizer(wx.HORIZONTAL)
        self.fileDropdown = wx.ComboBox(self, style=wx.CB_READONLY)
        viewButton = wx.Button(self, label="View")
        viewButton.Bind(wx.EVT_BUTTON, self.OnViewButtonClick)

        hbox.Add(self.fileDropdown, proportion=1, flag=wx.EXPAND | wx.RIGHT, border=10)
        hbox.Add(viewButton, flag=wx.EXPAND)
        vbox.Add(hbox, flag=wx.EXPAND | wx.ALL, border=10)

        self.resultsWindow = wx.TextCtrl(
            self, style=wx.TE_MULTILINE | wx.TE_READONLY | wx.TE_RICH2
        )
        self.resultsWindow.SetFont(
            wx.Font(
                10, wx.FONTFAMILY_TELETYPE, wx.FONTSTYLE_NORMAL, wx.FONTWEIGHT_NORMAL
            )
        )
        vbox.Add(self.resultsWindow, proportion=1, flag=wx.EXPAND | wx.ALL, border=10)

        self.SetSizer(vbox)

    def PopulateFileDropdown(self):
        stringFiles = [str(TARGET_FILE)]
        data = LoadFilesJson(self.analysisDir)
        if "error" not in data:
            for file in data.keys():
                if data[file].get("category", "") in ("files", "CAPE", "procdump"):
                    path = os.path.join(file)
                    stringFiles.append(path)

        if stringFiles:
            self.fileDropdown.SetItems(stringFiles)
            self.fileDropdown.SetSelection(0)

        return stringFiles

    def OnViewButtonClick(self, event):
        selectedFile = self.fileDropdown.GetValue()
        self.LoadStringsResults(selectedFile)

    def LoadStringsResults(self, filename):
        path = Path(self.analysisDir, filename)
        if not path.exists():
            self.resultsWindow.SetValue("Selected file does not exist.")
            return
        stringsData = self.GetStrings(path)
        if not stringsData:
            stringsData = "No strings."
        self.resultsWindow.SetValue(stringsData)

    def GetStrings(self, filePath, minLength=4):
        encodings = ["utf-8", "utf-16"]
        text = ""
        for encoding in encodings:
            try:
                text = filePath.read_text(encoding=encoding)
                break
            except Exception:
                continue

        if not text:
            try:
                text = filePath.read_bytes().decode("ascii")
            except Exception:
                text = filePath.read_bytes().decode("latin-1")

        wordRegex = re.compile(r"\b\w{" + str(minLength) + r",}\b", re.UNICODE)
        words = wordRegex.findall(text)
        regex = re.compile(
            r"^[a-zA-Z0-9 \-\'àáâäãåçèéêëìíîïðñòóôöõùúûüýÿĀāĂăĄąÇćČčĎďĐđĒēĖėĘęĚěĞğĜĝĠġĢģĤĥĦħİıĴĵĶķĹĺĻļĽľŁłŃńŅņŇňŌōŎŏŐőŔŕŖŗŘřŚśŞşŠšŢţŤťŦŧŨũŪūŮůŰűŲųŴŵŶŷŸźżŽž]+$"
        )
        filteredWords = [word for word in words if regex.match(word)]
        filteredWords = sorted(list(set(filteredWords)), key=lambda x: (x, len(x)))

        return "\n".join(filteredWords)


class DebuggerPanel(wx.Panel, KeyEventHandlerMixin):
    def __init__(self, parent):
        super(DebuggerPanel, self).__init__(parent)
        self.analysisDir = parent.analysisDir
        self.BindKeyEvents()
        self.InitUI()

    def InitUI(self):
        vbox = wx.BoxSizer(wx.VERTICAL)

        hbox = wx.BoxSizer(wx.HORIZONTAL)
        self.logFileDropdown = wx.ComboBox(self, style=wx.CB_READONLY)
        viewButton = wx.Button(self, label="View")
        viewButton.Bind(wx.EVT_BUTTON, self.OnViewButtonClick)

        hbox.Add(
            self.logFileDropdown, proportion=1, flag=wx.EXPAND | wx.RIGHT, border=10
        )
        hbox.Add(viewButton, flag=wx.EXPAND)
        vbox.Add(hbox, flag=wx.EXPAND | wx.ALL, border=10)

        self.resultsWindow = wx.TextCtrl(
            self, style=wx.TE_MULTILINE | wx.TE_READONLY | wx.TE_RICH2
        )
        self.resultsWindow.SetFont(
            wx.Font(
                10, wx.FONTFAMILY_TELETYPE, wx.FONTSTYLE_NORMAL, wx.FONTWEIGHT_NORMAL
            )
        )
        vbox.Add(self.resultsWindow, proportion=1, flag=wx.EXPAND | wx.ALL, border=10)

        self.SetSizer(vbox)

    def PopulateLogFileDropdown(self):
        path = Path(self.analysisDir, "debugger")
        try:
            logFiles = [file.name for file in path.iterdir() if file.is_file()]
            self.logFileDropdown.SetItems(logFiles)
            if logFiles:
                self.logFileDropdown.SetSelection(0)
        except FileNotFoundError:
            return

    def OnViewButtonClick(self, event):
        selectedFile = self.logFileDropdown.GetValue()
        self.LoadDebuggerResults(selectedFile)

    def LoadDebuggerResults(self, file_name):
        path = Path(self.analysisDir, "debugger") / file_name
        if not path.exists():
            self.resultsWindow.SetValue("Selected log file does not exist.")
            return
        self.resultsWindow.SetValue(path.read_text())


class MainFrame(wx.Frame):
    def __init__(self, *args, **kwargs):
        self.version = Path("version.txt").read_text()
        kwargs["title"] = f"Capesolo - v{self.version}"
        super(MainFrame, self).__init__(*args, **kwargs)
        self.SetAppIcon()
        self.logger_window = None
        self.GetConfig()
        self.CreateAnalysisDirectory()
        self.InitUi()
        self.Bind(wx.EVT_CLOSE, self.OnClose)

    def InitUi(self):
        self.panel = wx.Panel(self)
        self.notebook = wx.Notebook(self.panel)
        self.notebook.analysisDir = self.analysisDir
        self.notebook.debug = self.debug
        self.notebook.yara = ProcessYara(self.analysisDir)
        self.startTab = StartPanel(self.notebook)
        self.notebook.AddPage(self.startTab, "Start")
        self.infoTab = TargetInfoPanel(self.notebook)
        self.notebook.AddPage(self.infoTab, "Info")
        self.behaviorTab = BehaviorPanel(self.notebook)
        self.notebook.AddPage(self.behaviorTab, "Behavior")
        self.payloadsTab = PayloadsPanel(self.notebook)
        self.notebook.AddPage(self.payloadsTab, "Payloads")
        self.yaraTab = YaraPanel(self.notebook)
        self.notebook.AddPage(self.yaraTab, "Yara")
        self.configsTab = ConfigsPanel(self.notebook)
        self.notebook.AddPage(self.configsTab, "Configs")
        self.stringsTab = StringsPanel(self.notebook)
        self.notebook.AddPage(self.stringsTab, "Strings")
        self.debuggerTab = DebuggerPanel(self.notebook)
        self.notebook.AddPage(self.debuggerTab, "Debugger")
        self.notebook.Bind(wx.EVT_NOTEBOOK_PAGE_CHANGED, self.OnNotebookPageChanged)

        # Layout
        sizer = wx.BoxSizer()
        sizer.Add(self.notebook, 1, wx.EXPAND)

        self.panel.SetSizer(sizer)

    def OnNotebookPageChanged(self, event):
        newSelection = event.GetSelection()
        selectedPage = self.notebook.GetPage(newSelection)
        if selectedPage == self.behaviorTab:
            selectedPage.UpdateGenerateButtonState()
        elif selectedPage == self.infoTab:
            selectedPage.LoadAndDisplayContent()
        elif selectedPage == self.payloadsTab:
            selectedPage.LoadAndDisplayContent()
        elif selectedPage == self.yaraTab:
            selectedPage.UpdateYaraButtonState()
        elif selectedPage == self.configsTab:
            selectedPage.UpdateConfigsButtonState()
        elif selectedPage == self.stringsTab:
            selectedPage.PopulateFileDropdown()
        elif selectedPage == self.debuggerTab:
            selectedPage.PopulateLogFileDropdown()

        event.Skip()

    def CreateAnalysisDirectory(self):
        with suppress(FileExistsError):
            path_mkdir(self.analysisDir)

    def GetConfig(self):
        configFile = os.path.join(CAPESOLO_ROOT, "cfg.ini")
        g_config = ConfigReader(configFile)
        analysisDir = g_config.analysis_directory.analysis
        if analysisDir:
            self.analysisDir = analysisDir
        self.debug = g_config.debug.enabled

    def SetAppIcon(self):
        icon = wx.Icon()
        iconPath = os.path.join(CAPESOLO_ROOT, "capesolo.png")
        icon.LoadFile(iconPath, wx.BITMAP_TYPE_PNG)
        self.SetIcon(icon)

    def OnClose(self, event):
        self.Destroy()


def main():
    parser = argparse.ArgumentParser(description="Capesolo utility functions.")
    parser.add_argument(
        "--update_yara",
        help="Update yara rules from CAPEv2 and community",
        action="store_true",
    )
    parser.add_argument(
        "--update_parsers", help="Update parser files from CAPEv2", action="store_true"
    )

    args = parser.parse_args()

    if args.update_yara:
        update_yara(Path(CAPESOLO_ROOT))
    elif args.update_parsers:
        update_parsers(Path(CAPESOLO_ROOT))
    else:
        app = CapesoloApp()
        app.MainLoop()


if __name__ == "__main__":
    main()
