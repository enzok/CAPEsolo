import wx

from CAPEsolo.capelib.cmdconsts import CMD_PATCH_BYTES
from .patch_models import PatchEntry


class PatchDialog(wx.Dialog):
    def __init__(self, parent):
        super().__init__(parent, title="Assemble Instructions", size=(400,300))
        vbox = wx.BoxSizer(wx.VERTICAL)
        self.textCtrl = wx.TextCtrl(self, style=wx.TE_MULTILINE)
        vbox.Add(self.textCtrl, 1, wx.EXPAND|wx.ALL, 5)
        hbox = wx.BoxSizer(wx.HORIZONTAL)
        hbox.Add(wx.Button(self, wx.ID_OK), 0, wx.RIGHT, 5)
        hbox.Add(wx.Button(self, wx.ID_CANCEL), 0)
        vbox.Add(hbox, 0, wx.ALIGN_CENTER|wx.ALL, 5)
        self.SetSizer(vbox)

    def GetAsmText(self) -> str:
        return self.textCtrl.GetValue()


class PatchHistoryDialog(wx.Dialog):
    """
    Dialog to display the global patch history.
    """
    def __init__(self, parent, patchHistory: list[PatchEntry]):
        super().__init__(parent, title="Patch History", size=(700, 400))
        self.parent = parent
        self.patchHistory = patchHistory
        vbox = wx.BoxSizer(wx.VERTICAL)

        self.listCtrl = wx.ListCtrl(self, style=wx.LC_REPORT | wx.BORDER_SUNKEN)
        self.listCtrl.InsertColumn(0, "Address", width=120)
        self.listCtrl.InsertColumn(1, "Original Bytes", width=150)
        self.listCtrl.InsertColumn(2, "Patched Bytes", width=150)
        self.listCtrl.InsertColumn(3, "Instruction", width=200)
        self.listCtrl.InsertColumn(4, "Timestamp", width=150)

        for entry in patchHistory:
            idx = self.listCtrl.InsertItem(self.listCtrl.GetItemCount(), f"0x{entry.address:08X}")
            self.listCtrl.SetItem(idx, 1, entry.originalBytes)
            self.listCtrl.SetItem(idx, 2, entry.patchedBytes)
            self.listCtrl.SetItem(idx, 3, entry.instruction)
            ts = entry.timeStamp.strftime("%Y-%m-%d %H:%M:%S")
            self.listCtrl.SetItem(idx, 4, ts)

        vbox.Add(self.listCtrl, 1, wx.EXPAND | wx.ALL, 5)
        btn = wx.Button(self, wx.ID_CLOSE, label="Close")
        vbox.Add(btn, 0, wx.ALIGN_CENTER | wx.ALL, 5)
        self.SetSizer(vbox)

        btn.Bind(wx.EVT_BUTTON, lambda evt: self.Close())
        self.listCtrl.Bind(wx.EVT_CONTEXT_MENU, self.OnContextMenu)
        self.Bind(wx.EVT_BUTTON, lambda evt: self.Close(), id=wx.ID_CLOSE)

    def OnContextMenu(self, event):
        pos = event.GetPosition()
        pos = self.ScreenToClient(pos)
        row, flags = self.HitTest(pos)
        if row == wx.NOT_FOUND:
            return

        menu = wx.Menu()
        miUndo = menu.Append(wx.ID_ANY, "Undo Patch")
        self.Bind(wx.EVT_MENU,lambda e: self.OnUndoPatch(row), miUndo)
        self.PopupMenu(menu)
        menu.Destroy()

    def OnUndoPatch(self, row):
        entry = self.patchHistory[row]
        addrStr = f"0x{entry.address:08X}"
        # Remove from host history lists
        self.parent.patchHistory.remove(entry)
        addrList = self.parent.patchHistoryByAddr.get(entry.address)
        if addrList:
            addrList.remove(entry)

        data = f"{addrStr}|{entry.originalBytes}"
        self.parent.SendCommand(CMD_PATCH_BYTES, data)
        self.listCtrl.DeleteItem(row)
        self.patchHistory.pop(row)
