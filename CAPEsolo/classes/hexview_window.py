import wx
import wx.lib.scrolledpanel as scrolled

from .key_event import KeyEventHandlerMixin
from .theme import FONT_CODE, apply_theme


class HexViewWindow(wx.Frame, KeyEventHandlerMixin):
    def __init__(
        self,
        parent,
        title,
        filepath,
        main_window_position,
        main_window_size,
        *args,
        **kwargs,
    ):
        super(HexViewWindow, self).__init__(parent, title=title, *args, **kwargs)
        self.panel = scrolled.ScrolledPanel(
            self, -1, style=wx.TAB_TRAVERSAL | wx.SUNKEN_BORDER
        )
        self.panel.SetAutoLayout(1)
        self.panel.SetupScrolling(scroll_x=True, scroll_y=True)
        self.vbox = wx.BoxSizer(wx.VERTICAL)
        self.filepath = filepath
        self.BindKeyEvents()
        self.mainWindowPosition = main_window_position
        self.mainWindowSize = main_window_size
        self.InitUI()

    def InitUI(self):
        self.vbox.AddSpacer(10)
        hex_data = self.ReadHexData(self.filepath)
        self.DisplayHexData(hex_data)
        self.panel.SetSizer(self.vbox)
        # Offset a copy: the caller reuses the wx.Point it passed in, so mutating it here
        # would silently move whatever it positions next.
        position = wx.Point(self.mainWindowPosition)
        position.x += self.mainWindowSize.x
        self.SetPosition(position)
        self.panel.Layout()
        self.Layout()
        apply_theme(self)

    def ReadHexData(self, filepath):
        try:
            data = filepath.read_bytes()
            return self.FormatHexData(data)
        except IOError as e:
            wx.LogError(f"Cannot open file '{filepath}'. Error: {e}")
            return ""

    def FormatHexData(self, data):
        lines = []
        for i in range(0, len(data), 16):
            chunk = data[i : i + 16]
            hexChunk = " ".join(f"{byte:02x}" for byte in chunk)
            asciiChunk = "".join(
                chr(byte) if 32 <= byte <= 126 else "." for byte in chunk
            )
            lines.append(f"{i:08x}  {hexChunk:<48}  {asciiChunk}")
        return "\n".join(lines)

    def DisplayHexData(self, hexdata):
        # FONT_CODE rather than a locally built teletype font: apply_theme only leaves a
        # TextCtrl's font alone when its face name is Consolas, so any other monospace font
        # would be replaced with the proportional UI font and the columns would misalign.
        font = FONT_CODE
        # The dump goes in after construction. Passing it as value= makes wxMSW hand the
        # whole string to CreateWindowEx as the window title, which fails outright for a
        # multi-megabyte payload ("CreateWindowEx(\"EDIT\", ... title-len=10123774)").
        textCtrl = wx.TextCtrl(
            self.panel,
            style=wx.TE_MULTILINE | wx.TE_READONLY | wx.HSCROLL,
        )
        textCtrl.SetFont(font)
        textCtrl.ChangeValue(hexdata)

        dc = wx.ClientDC(textCtrl)
        dc.SetFont(font)
        textWidth, _ = dc.GetTextExtent(hexdata.split("\n")[0])

        self.SetSize(textWidth + 80, self.mainWindowSize.y)
        self.vbox.Add(textCtrl, 1, wx.EXPAND | wx.ALL, 10)
