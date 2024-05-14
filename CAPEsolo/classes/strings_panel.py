import os
import re
from pathlib import Path

import wx

from .key_event import KeyEventHandlerMixin
from CAPEsolo.capelib.utils import LoadFilesJson


class StringsPanel(wx.Panel, KeyEventHandlerMixin):
    def __init__(self, parent):
        super(StringsPanel, self).__init__(parent)
        self.parent = parent
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
        self.targetFile = self.parent.targetFile
        stringFiles = [str(self.targetFile)]
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
