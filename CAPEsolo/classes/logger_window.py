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
        screenWidth, _ = wx.DisplaySize()
        self.SetSize(int(screenWidth * 0.98 - self.main_window_size.x), self.main_window_size.y)
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
