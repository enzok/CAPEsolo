import os

import wx
import wx.adv


class SplashScreen(wx.adv.SplashScreen):
    """The startup splash.

    wx.adv.SplashScreen draws the bitmap at its own pixel size, so the file's dimensions are
    the splash's dimensions - there is nothing to scale it here. capesolo_splash.png is
    rendered at 512 from the 2048px artwork for that reason; capesolo.png, which this used
    before, is 256 and was sized to be an icon.
    """

    def __init__(self, capesoloRoot):
        bitmap = wx.Bitmap(os.path.join(capesoloRoot, "capesolo_splash.png"))
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
