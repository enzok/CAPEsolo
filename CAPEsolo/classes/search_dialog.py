import wx


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
