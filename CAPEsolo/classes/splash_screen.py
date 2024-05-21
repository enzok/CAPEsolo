import os
import wx
import wx.adv


class SplashScreen(wx.adv.SplashScreen):
    def __init__(self, capesoloRoot):
        bitmap = wx.Bitmap(os.path.join(capesoloRoot, "capesolo.png"))
        super().__init__(
            bitmap,
            wx.adv.SPLASH_CENTRE_ON_SCREEN | wx.adv.SPLASH_TIMEOUT,
            2000,
            None,
            -1,
        )
        self.Bind(wx.EVT_CLOSE, self.OnClose)
        self.fc = wx.CallLater(1000, self.UpdateCountdown, 2)

    def OnClose(self, event):
        self.fc.Stop()
        event.Skip()

    def UpdateCountdown(self, count):
        if count > 0:
            self.fc.Restart(1000, self.UpdateCountdown, count - 1)
        else:
            self.Close()
