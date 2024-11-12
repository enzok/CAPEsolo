import wx

class CountdownTimer(wx.Frame):
    def __init__(self, parent, countdown, main_window_position, main_window_size, *args, **kwargs):
        super(CountdownTimer, self).__init__(parent, title="Analysis Time Remaining", style=wx.DEFAULT_FRAME_STYLE & ~(wx.CLOSE_BOX | wx.MINIMIZE_BOX | wx.MAXIMIZE_BOX), *args, **kwargs)
        self.parent = parent
        self.countdown = countdown

        panel = wx.Panel(self)
        hbox = wx.BoxSizer(wx.HORIZONTAL)

        main_window_position.y += main_window_size.y + 2
        self.SetPosition(main_window_position)
        self.SetSize(200, 100)

        self.timerLabel = wx.StaticText(panel, label=f"{self.countdown}", style=wx.ALIGN_CENTER)
        font = self.timerLabel.GetFont()
        font.PointSize += 10
        self.timerLabel.SetFont(font)
        hbox.Add(self.timerLabel, flag=wx.ALIGN_CENTER_VERTICAL | wx.ALL, border=10)
        closeButton = wx.Button(panel, label="Close")
        closeButton.Bind(wx.EVT_BUTTON, self.OnClose)
        hbox.Add(closeButton,flag=wx.ALIGN_CENTER_VERTICAL | wx.ALL, border=10)

        panel.SetSizerAndFit(hbox)

        self.parent.timer = wx.Timer(self)
        self.Bind(wx.EVT_TIMER, self.OnTimerTick, self.parent.timer)
        self.parent.timer.Start(1000)
        self.Layout()
        self.Fit()

    def OnClose(self, event):
        self.Hide()

    def OnTimerTick(self, event):
        if self.countdown > 0:
            self.countdown -= 1
            self.timerLabel.SetLabel(f"{self.countdown}s")
            self.Layout()
        else:
            self.parent.timer.Stop()
