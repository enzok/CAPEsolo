from wx import NewIdRef, PyEventBinder, EVT_CHAR_HOOK

from .search_dialog import SearchDialog

EVT_ANALYZER_COMPLETE_ID = NewIdRef()
EVT_ANALYZER_COMPLETE = PyEventBinder(EVT_ANALYZER_COMPLETE_ID, 1)


class KeyEventHandlerMixin:
    def BindKeyEvents(self):
        self.Bind(EVT_CHAR_HOOK, self.OnKeyDown)

    def OnKeyDown(self, event):
        if event.GetKeyCode() == ord("F") and event.ControlDown():
            dlg = SearchDialog(self)
            dlg.ShowModal()
            dlg.Destroy()
        else:
            event.Skip()