from pathlib import Path

import wx

from .key_event import KeyEventHandlerMixin


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
