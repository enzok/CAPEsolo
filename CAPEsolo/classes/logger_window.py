import logging

import wx

from .key_event import KeyEventHandlerMixin


class WxTextCtrlHandler(logging.Handler):
    def __init__(self, textctrl):
        super(WxTextCtrlHandler, self).__init__()
        self.textctrl = textctrl

    def emit(self, record):
        msg = self.format(record)
        wx.CallAfter(self.textctrl.AppendText, msg + "\n")


class LoggerWindow(wx.Frame, KeyEventHandlerMixin):
    def __init__(
        self, parent, title, main_window_position, main_window_size, *args, **kwargs
    ):
        super(LoggerWindow, self).__init__(parent, title=title, *args, **kwargs)
        self.analysisDir = parent.analysisDir
        self.analysisLogPath = parent.analysisLogPath
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
        fontCourier = wx.Font(
            10, wx.FONTFAMILY_MODERN, wx.FONTSTYLE_NORMAL, wx.FONTWEIGHT_NORMAL
        )
        self.resultsWindow.SetFont(fontCourier)
        vbox.Add(self.resultsWindow, proportion=1, flag=wx.EXPAND | wx.ALL, border=5)
        copyPathBtn = wx.Button(panel, label="Copy Log")
        copyPathBtn.Bind(wx.EVT_BUTTON, self.OnCopyPath)
        vbox.Add(copyPathBtn, proportion=0, flag=wx.ALL | wx.CENTER, border=5)
        panel.SetSizer(vbox)

        fileHandler = logging.FileHandler(self.analysisLogPath)
        wxHandler = WxTextCtrlHandler(self.resultsWindow)
        logging.basicConfig(
            level=logging.DEBUG,
            handlers=[fileHandler, wxHandler],
            format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
        )

        self.main_window_position.x += self.main_window_size.x
        screenWidth, _ = wx.DisplaySize()
        self.SetSize(
            int(screenWidth * 0.98 - self.main_window_size.x), self.main_window_size.y
        )
        self.SetPosition(self.main_window_position)

    def OnCopyPath(self, event):
        if wx.TheClipboard.Open():
            file_data = wx.FileDataObject()
            file_data.AddFile(self.analysisLogPath)
            wx.TheClipboard.SetData(file_data)
            wx.TheClipboard.Close()
            wx.MessageBox(
                f"Analysis log copied: {self.analysisLogPath}",
                "Info",
                wx.OK | wx.ICON_INFORMATION,
            )
        else:
            wx.LogError("Unable to open the clipboard.")
