import json

import wx
import wx.grid as gridlib
import wx.lib.scrolledpanel as scrolled

from .key_event import KeyEventHandlerMixin
from CAPEsolo.capelib.parse_pe import PortableExecutable


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
        screenWidth, _ = wx.DisplaySize()
        self.SetSize(
            int(screenWidth * 0.98 - self.main_window_size.x), self.main_window_size.y
        )
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
