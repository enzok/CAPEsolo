import re

import wx


class SearchDialog(wx.Dialog):
    def __init__(self, parent):
        super(SearchDialog, self).__init__(
            parent,
            title="Find",
            size=wx.Size(400, 100),
            style=wx.DEFAULT_DIALOG_STYLE | wx.STAY_ON_TOP,
        )
        self.caseSensitive = False
        self.fullWord = False
        if hasattr(parent, "grid"):
            self.grid = parent.grid
            self.Finder = self.FindCell
            self.FinderNext = self.FindNextCell
            self.currentSearchPos = (0, 0)
        elif hasattr(parent, "listCtrl"):
            self.listCtrl = parent.listCtrl
            self.Finder = self.FindInList
            self.FinderNext = self.FindInListNext
            self.currentSearchPos = (0, 0)
        else:
            self.resultsWindow = parent.resultsWindow
            self.lastFoundPos = -1
            self.Finder = self.OnFind
            self.FinderNext = self.OnFindNext

        self.InitUi()
        self.findWindow.Bind(wx.EVT_TEXT_ENTER, self.Finder)

    def InitUi(self):
        sizer = wx.BoxSizer(wx.VERTICAL)
        self.findWindow = wx.TextCtrl(self, style=wx.TE_PROCESS_ENTER)

        findButton = wx.Button(self, label="Find")
        findButton.Bind(wx.EVT_BUTTON, self.Finder)
        findNextButton = wx.Button(self, label="Find Next")
        findNextButton.Bind(wx.EVT_BUTTON, self.FinderNext)

        hbox1 = wx.BoxSizer(wx.HORIZONTAL)
        hbox1.Add(findButton, proportion=1, flag=wx.EXPAND | wx.RIGHT, border=5)
        hbox1.Add(findNextButton, proportion=1, flag=wx.EXPAND)


        self.chkCase = wx.CheckBox(self, label="Aa")
        self.chkCase.SetValue(False)
        self.chkCase.Bind(wx.EVT_CHECKBOX, self.OnCaseToggle)

        self.chkFull = wx.CheckBox(self, label="\u00A6ab\u00A6")
        self.chkFull.SetValue(False)
        self.chkFull.Bind(wx.EVT_CHECKBOX, self.OnFullWordToggle)

        hbox2 = wx.BoxSizer(wx.HORIZONTAL)
        hbox2.Add(self.chkCase, flag=wx.RIGHT, border=10)
        hbox2.Add(self.chkFull)

        sizer.Add(self.findWindow, proportion=0, flag=wx.EXPAND | wx.ALL, border=5)
        sizer.Add(hbox1, proportion=0, flag=wx.EXPAND | wx.ALL, border=5)
        sizer.Add(hbox2, proportion=0, flag=wx.ALIGN_CENTER_HORIZONTAL | wx.ALL, border=5)

        self.SetSizer(sizer)
        self.Fit()

    def OnFind(self, event):
        self.FindText()

    def OnFindNext(self, event):
        self.FindText(startPos=self.lastFoundPos + 1)

    def FindText(self, startPos=0):
        searchText = self.findWindow.GetValue()
        content = self.resultsWindow.GetValue()
        if not self.caseSensitive:
            searchText = searchText.lower()
            content = content.lower()

        self.lastFoundPos = -1
        if self.fullWord:
            pattern = r'\b' + re.escape(searchText) + r'\b'
            match = re.search(pattern, content[startPos:])
            if match:
                self.lastFoundPos = startPos + match.start()
        else:
            self.lastFoundPos = content.find(searchText, startPos)

        self.HighlightText()

    def HighlightText(self):
        if self.lastFoundPos != -1:
            searchText = self.findWindow.GetValue()
            searchTextLength = len(searchText)
            textCtrl = self.resultsWindow
            backgroundColor = wx.SystemSettings.GetColour(wx.SYS_COLOUR_WINDOW)
            textCtrl.SetStyle(self.lastFoundPos, self.lastFoundPos + searchTextLength, wx.TextAttr("red", backgroundColor))
            textCtrl.ShowPosition(self.lastFoundPos)
            wx.CallLater(5000, self.ResetHighlight, textCtrl, self.lastFoundPos, searchTextLength)
            textCtrl.SetInsertionPoint(self.lastFoundPos)
            textCtrl.SetFocus()
        else:
            wx.MessageBox("Text not found.", "Search Result", wx.OK | wx.ICON_INFORMATION)

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

    def SearchCells(self):
        match = False
        searchText = self.findWindow.GetValue()
        if not self.caseSensitive:
            searchText = searchText.lower()

        rows = self.grid.GetNumberRows()
        cols = self.grid.GetNumberCols()
        startRow, startCol = self.currentSearchPos
        for row in range(startRow, rows):
            for col in range(startCol if row == startRow else 0, cols):
                cellText = self.grid.GetCellValue(row, col)
                cmpText = cellText if self.caseSensitive else cellText.lower()
                if self.fullWord:
                    match = searchText == cmpText
                else:
                    match = searchText in cmpText

                if match:
                    self.grid.SetGridCursor(row, col)
                    self.grid.MakeCellVisible(row, col)
                    self.grid.SelectBlock(row, col, row, col)
                    self.currentSearchPos = (row, col + 1)

                    if self.currentSearchPos[1] >= cols:
                        self.currentSearchPos = (self.currentSearchPos[0] + 1, 0)
                    return

        if not match:
            wx.MessageBox(f"'{searchText}' not found.", "Search Result", wx.OK | wx.ICON_INFORMATION)

        self.currentSearchPos = (0, 0)

    def FindCell(self, event):
        self.currentSearchPos = (0, 0)
        self.SearchCells()

    def FindNextCell(self, event):
        self.SearchCells()

    def SearchList(self):
        match = False
        searchText = self.findWindow.GetValue()
        if not self.caseSensitive:
            searchText = searchText.lower()

        rows = self.listCtrl.GetItemCount()
        cols = self.listCtrl.GetColumnCount()
        startRow = self.currentSearchRow

        for row in range(startRow, rows):
            for col in range(cols):
                cellText = self.listCtrl.GetItem(row, col).GetText()
                cmpText = cellText if self.caseSensitive else cellText.lower()
                if self.fullWord:
                    match = searchText == cmpText
                else:
                    match = searchText in cmpText

                if match:
                    self.listCtrl.Select(row)
                    self.listCtrl.Focus(row)
                    self.listCtrl.EnsureVisible(row)
                    self.currentSearchRow = row + 1

                    if self.currentSearchRow >= rows:
                        self.currentSearchRow = 0
                    return

        if not match:
            wx.MessageBox(f"'{searchText}' not found.", "Search Result", wx.OK | wx.ICON_INFORMATION)

        self.currentSearchRow = 0

    def FindInList(self, event):
        self.currentSearchRow = 0
        self.SearchList()

    def FindInListNext(self, event):
        self.SearchList()

    def OnCaseToggle(self, event):
        self.caseSensitive = self.chkCase.GetValue()

    def OnFullWordToggle(self, event):
        self.fullWord = self.chkFull.GetValue()
