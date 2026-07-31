from pathlib import Path

import wx
import wx.grid as gridlib

from .custom_grid import CopyableGrid
from .pe_window import PeWindow
from .theme import GRID_ROW_ALT, apply_theme
from CAPEsolo.capelib.objects import File


class TargetInfoPanel(wx.Panel):
    def __init__(self, parent):
        super(TargetInfoPanel, self).__init__(parent)
        self.parent = parent
        self.infoLoaded = False
        self.peData = {}
        # Whatever the grid is currently describing, which the PE button acts on. Not
        # necessarily the analysis target: Get Info can show an arbitrary file.
        self.displayedFile = None
        self.InitUI()

    def InitUI(self):
        vbox = wx.BoxSizer(wx.VERTICAL)
        vbox.AddSpacer(10)
        self.grid = CopyableGrid(self,0, 2)
        self.grid.SetColLabelSize(0)
        self.grid.SetRowLabelSize(0)

        for col in range(self.grid.GetNumberCols()):
            attr = gridlib.GridCellAttr()
            attr.SetAlignment(wx.ALIGN_CENTRE, wx.ALIGN_CENTRE)
            self.grid.SetColAttr(col, attr)

        leftAttr0 = gridlib.GridCellAttr()
        leftAttr0.SetAlignment(wx.ALIGN_LEFT, wx.ALIGN_CENTRE)
        self.grid.SetColAttr(0, leftAttr0)

        leftAttr1 = gridlib.GridCellAttr()
        leftAttr1.SetAlignment(wx.ALIGN_LEFT, wx.ALIGN_CENTRE)
        self.grid.SetColAttr(1, leftAttr1)
        self.grid.EnableEditing(False)
        vbox.Add(self.grid, proportion=1, flag=wx.EXPAND | wx.ALL, border=5)

        hboxButtons = wx.BoxSizer(wx.HORIZONTAL)
        self.getInfoButton = wx.Button(self, label="Get Info")
        self.getInfoButton.SetToolTip(
            "Inspect the file currently selected on the Start tab. Display only - the "
            "file is not copied, analysed or recorded."
        )
        self.getInfoButton.Bind(wx.EVT_BUTTON, self.OnGetInfo)
        hboxButtons.Add(self.getInfoButton, proportion=0, flag=wx.RIGHT, border=5)
        self.peButton = wx.Button(self, label="PE")
        self.peButton.Bind(wx.EVT_BUTTON, self.OnShowPe)
        self.peButton.Hide()
        hboxButtons.Add(self.peButton, proportion=0)
        vbox.Add(hboxButtons, proportion=0, flag=wx.LEFT | wx.BOTTOM, border=5)

        self.SetSizer(vbox)
        apply_theme(self)

    def AddNewRow(self, value0, value1):
        current_row = self.grid.GetNumberRows()
        self.grid.AppendRows(1)
        self.grid.SetCellValue(current_row, 0, value0)
        self.grid.SetCellValue(current_row, 1, value1)

    def ClearGrid(self):
        rows = self.grid.GetNumberRows()
        if rows:
            self.grid.DeleteRows(0, rows)

    def PopulateGrid(self, path):
        """Render file info for *path*. Nothing is written anywhere."""
        self.ClearGrid()
        fileObj = File(str(path))
        fileinfo = fileObj.get_all()[0]
        self.AddNewRow("Path", str(path))
        for key, value in fileinfo.items():
            if key not in "path" and value:
                if not isinstance(value, str):
                    value = str(value) + " bytes"
                if value.startswith("s_"):
                    value = value[2:]
                self.AddNewRow(key[0].upper() + key[1:], value)
        self.grid.AutoSizeColumns()
        self.grid.SetColSize(0, 120)
        self.grid.AutoSizeRows()
        self.ApplyAlternateRowShading()
        self.displayedFile = Path(path)
        self.peButton.Show()
        self.Layout()

    def LoadAndDisplayContent(self):
        self.targetFile = self.parent.targetFile
        if self.infoLoaded or not self.targetFile:
            return
        self.PopulateGrid(self.targetFile)
        self.infoLoaded = True

    def OnGetInfo(self, event):
        """Show info for the file selected on the Start tab, without touching it.

        Deliberately does not set parent.targetFile, copy the file into the analysis
        directory or record anything: this is a look, not a submission. infoLoaded is
        left alone so a later analysis still replaces this with the real target's info.
        """
        startTab = getattr(self.GetMainFrame(), "startTab", None)
        selected = startTab.targetPath.GetValue().strip() if startTab else ""
        if not selected:
            wx.MessageBox(
                "No target file selected. Choose one on the Start tab first.",
                "No Target",
                wx.OK | wx.ICON_INFORMATION,
            )
            return

        path = Path(selected)
        if not path.is_file():
            wx.MessageBox(
                f"Not a readable file:\n{path}", "Error", wx.OK | wx.ICON_ERROR
            )
            return

        try:
            # get_all() hashes the whole file, so a large sample takes a moment.
            with wx.BusyCursor():
                self.PopulateGrid(path)
        except Exception as e:
            wx.MessageBox(
                f"Failed to read file info: {e}", "Error", wx.OK | wx.ICON_ERROR
            )

    def ApplyAlternateRowShading(self):
        numRows = self.grid.GetNumberRows()

        for row in range(numRows):
            if row % 2 == 0:
                attr = gridlib.GridCellAttr()
                attr.SetBackgroundColour(GRID_ROW_ALT)
                self.grid.SetRowAttr(row, attr)
        self.grid.ForceRefresh()

    def OnShowPe(self, event):
        try:
            main_frame = self.GetMainFrame()
            size = main_frame.GetSize()
            position = main_frame.GetPosition()
            # displayedFile, not targetFile: the grid may be showing an ad-hoc file.
            viewer_window = PeWindow(
                self, f"{str(self.displayedFile)}", self.displayedFile, position, size
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
