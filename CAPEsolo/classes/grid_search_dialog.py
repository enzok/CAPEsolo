import wx


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
