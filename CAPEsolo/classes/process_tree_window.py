import logging
import os
import re
from pathlib import Path
from threading import Thread

import wx

from .process_tools import (
    dump_process_memory,
    resume_process,
    snapshot_processes,
    suspend_process,
    terminate_process,
)
from .theme import apply_theme

log = logging.getLogger(__name__)

REFRESH_MS = 1500
EXITED_COLOUR = wx.Colour(140, 140, 140)

# The ResultServer's process line as written to analysis.log (resultserver.py:625):
#   "Process <pid> (parent <ppid>): <name>, path <module_path>"
# This is the authoritative, parented set of monitored processes and is exactly what the analyst
# sees in the log, so parsing the log file (rather than the .bson logs or a logging handler that may
# not receive the record) makes the tree match the log. Read straight from the text file - no
# injecting/hooking, so capemon is undisturbed.
PROC_RE = re.compile(r"Process (\d+) \(parent (\d+)\): (.+?), path (.+?)\s*$")


class ProcessTreeWindow(wx.Frame):
    """The analysis process tree, sourced from analysis.log's process lines so it matches the log
    and the Behavior tab. A periodic external snapshot only flips live nodes to [exited]. Right-click
    a live process to suspend/resume, terminate (cooperatively via capemon first) or memory-dump it."""

    def __init__(self, parent, title, position):
        super().__init__(parent, title=title)
        self.startPanel = parent
        self.model = {}         # pid -> {"ppid","name","path","alive"}
        self.itemByPid = {}     # pid -> wx.TreeItemId
        self.suspended = set()
        self._structSig = None
        self.logPath = Path(parent.analysisDir) / "analysis.log"
        self._logPos = 0        # byte offset consumed so far (complete lines only)
        self.InitUI(position)
        self.Bind(wx.EVT_CLOSE, self.OnClose)
        self.timer = wx.Timer(self)
        self.Bind(wx.EVT_TIMER, self.OnTimer)
        self.timer.Start(REFRESH_MS)
        wx.CallAfter(self._Tick)

    def InitUI(self, position):
        panel = wx.Panel(self)
        vbox = wx.BoxSizer(wx.VERTICAL)
        self.tree = wx.TreeCtrl(
            panel,
            style=wx.TR_DEFAULT_STYLE | wx.TR_HIDE_ROOT | wx.TR_HAS_BUTTONS | wx.TR_LINES_AT_ROOT,
        )
        self.root = self.tree.AddRoot("Processes")
        self.tree.Bind(wx.EVT_TREE_ITEM_GETTOOLTIP, self.OnItemTooltip)
        self.tree.Bind(wx.EVT_TREE_ITEM_RIGHT_CLICK, self.OnRightClick)
        vbox.Add(self.tree, proportion=1, flag=wx.EXPAND | wx.ALL, border=5)
        panel.SetSizer(vbox)
        apply_theme(self)
        self.SetSize(wx.Size(520, 640))
        self.SetPosition(wx.Point(position.x + 40, position.y + 40))

    # --- data ---------------------------------------------------------------
    def _analyzer(self):
        return getattr(self.startPanel, "analyzer", None)

    def _blocked(self):
        analyzer = self._analyzer()
        blocked = set(getattr(analyzer, "CRITICAL_PROCESS_LIST", None) or [])
        blocked.add(os.getpid())
        return blocked

    def _ScanLog(self):
        """Read new complete lines from analysis.log and add a node per 'Process N (parent M)' line."""
        try:
            size = self.logPath.stat().st_size
        except OSError:
            return
        if size < self._logPos:  # rotated/truncated - start over
            self._logPos = 0
        if size <= self._logPos:
            return
        try:
            with self.logPath.open("rb") as f:
                f.seek(self._logPos)
                chunk = f.read()
        except OSError:
            return
        # Only consume up to the last newline so a half-written final line is re-read next tick.
        lastNl = chunk.rfind(b"\n")
        if lastNl == -1:
            return
        self._logPos += lastNl + 1
        for line in chunk[: lastNl + 1].decode("utf-8", errors="replace").splitlines():
            m = PROC_RE.search(line)
            if not m:
                continue
            pid, ppid = int(m.group(1)), int(m.group(2))
            if pid in self.model:  # keep the first sighting; never resurrect an exited pid
                continue
            self.model[pid] = {
                "ppid": ppid, "name": m.group(3), "path": m.group(4), "alive": True,
            }

    def OnTimer(self, event):
        self._Tick()

    def _Tick(self):
        self._ScanLog()
        # Membership comes from the log; the snapshot only says which known pids are still alive.
        # Only flip alive -> exited (never resurrect), so a reused PID can't revive an exited node.
        snap = snapshot_processes()
        for pid, entry in self.model.items():
            if entry["alive"] and pid not in snap:
                entry["alive"] = False
        self._Render()

    # --- rendering ----------------------------------------------------------
    def _Render(self):
        sig = frozenset(
            (pid, e["ppid"] if e["ppid"] in self.model else 0) for pid, e in self.model.items()
        )
        if sig != self._structSig:
            self._structSig = sig
            self._Rebuild()
        else:
            for pid, entry in self.model.items():
                item = self.itemByPid.get(pid)
                if item and item.IsOk():
                    self._StyleItem(item, pid, entry)

    def _StyleItem(self, item, pid, entry):
        label = f'{entry["name"]} ({pid})'
        if not entry["alive"]:
            label += " [exited]"
        elif pid in self.suspended:
            label += " [suspended]"
        self.tree.SetItemText(item, label)
        colour = self.tree.GetForegroundColour() if entry["alive"] else EXITED_COLOUR
        self.tree.SetItemTextColour(item, colour)

    def _Rebuild(self):
        sel = self.tree.GetSelection()
        selPid = self.tree.GetItemData(sel) if sel.IsOk() else None
        expanded = {
            pid for pid, item in self.itemByPid.items() if item.IsOk() and self.tree.IsExpanded(item)
        }
        self.tree.Freeze()
        try:
            self.tree.DeleteAllItems()
            self.root = self.tree.AddRoot("Processes")
            self.itemByPid = {}
            # Add parents before children so every node has a real parent item.
            remaining = dict(self.model)
            progress = True
            while remaining and progress:
                progress = False
                for pid in list(remaining):
                    ppid = remaining[pid]["ppid"]
                    if ppid in self.model and ppid not in self.itemByPid:
                        continue  # parent not placed yet
                    parent = self.itemByPid.get(ppid, self.root)
                    self._AddNode(parent, pid, remaining.pop(pid))
                    progress = True
            for pid in list(remaining):  # orphans/cycles: attach to root
                self._AddNode(self.root, pid, remaining.pop(pid))

            for pid in expanded:
                item = self.itemByPid.get(pid)
                if item and item.IsOk() and self.tree.ItemHasChildren(item):
                    self.tree.Expand(item)
            for pid, item in self.itemByPid.items():  # top-level nodes expanded by default
                if self.model[pid]["ppid"] not in self.model and self.tree.ItemHasChildren(item):
                    self.tree.Expand(item)
            if selPid is not None and selPid in self.itemByPid:
                self.tree.SelectItem(self.itemByPid[selPid])
        finally:
            self.tree.Thaw()

    def _AddNode(self, parent, pid, entry):
        item = self.tree.AppendItem(parent, "")
        self.tree.SetItemData(item, pid)
        self.itemByPid[pid] = item
        self._StyleItem(item, pid, entry)

    def OnItemTooltip(self, event):
        entry = self.model.get(self.tree.GetItemData(event.GetItem()))
        if entry and entry.get("path"):
            event.SetToolTip(entry["path"])

    # --- actions ------------------------------------------------------------
    def _actionable(self, pid, entry):
        return entry["alive"] and pid not in self._blocked()

    def OnRightClick(self, event):
        item = event.GetItem()
        if not item.IsOk():
            return
        self.tree.SelectItem(item)
        pid = self.tree.GetItemData(item)
        entry = self.model.get(pid)
        if not entry:
            return
        enabled = self._actionable(pid, entry)

        menu = wx.Menu()
        suspendItem = menu.Append(wx.ID_ANY, "Resume" if pid in self.suspended else "Suspend")
        terminateItem = menu.Append(wx.ID_ANY, "Terminate")
        dumpItem = menu.Append(wx.ID_ANY, "Memory Dump")
        for mi in (suspendItem, terminateItem, dumpItem):
            mi.Enable(enabled)
        menu.Bind(wx.EVT_MENU, lambda evt: self._OnSuspendResume(pid), suspendItem)
        menu.Bind(wx.EVT_MENU, lambda evt: self._OnTerminate(pid), terminateItem)
        menu.Bind(wx.EVT_MENU, lambda evt: self._OnDump(pid), dumpItem)
        self.tree.PopupMenu(menu)
        menu.Destroy()

    def _OnSuspendResume(self, pid):
        try:
            if pid in self.suspended:
                resume_process(pid)
                self.suspended.discard(pid)
                self._SetStatus(f"Resumed pid {pid}")
            else:
                suspend_process(pid)
                self.suspended.add(pid)
                self._SetStatus(f"Suspended pid {pid}")
        except OSError as e:
            wx.MessageBox(str(e), "Process Tree", wx.OK | wx.ICON_ERROR)
        self._Render()

    def _OnTerminate(self, pid):
        name = self.model.get(pid, {}).get("name", str(pid))
        if wx.MessageBox(
            f"Terminate {name} ({pid})?\n\nCapemon is asked to shut it down cleanly first; if it "
            "does not exit it is force-killed. Monitoring of this process ends.",
            "Terminate Process",
            wx.YES_NO | wx.ICON_WARNING,
            self,
        ) != wx.YES:
            return
        self._SetStatus(f"Terminating {name} ({pid})...")

        def worker():
            try:
                how = terminate_process(pid)
                wx.CallAfter(self._AfterTerminate, pid, how, None)
            except OSError as e:
                wx.CallAfter(self._AfterTerminate, pid, None, str(e))

        Thread(target=worker, daemon=True).start()

    def _AfterTerminate(self, pid, how, err):
        if err:
            self._SetStatus("Terminate failed")
            wx.MessageBox(err, "Process Tree", wx.OK | wx.ICON_ERROR)
        else:
            self.suspended.discard(pid)
            self._SetStatus(f"Terminated pid {pid} ({how})")

    def _OnDump(self, pid):
        name = self.model.get(pid, {}).get("name", str(pid))
        dest = Path(self.startPanel.analysisDir) / "memory" / f"{pid}.dmp"
        self._SetStatus(f"Dumping {name} ({pid})...")

        def worker():
            try:
                path = dump_process_memory(pid, dest)
                wx.CallAfter(self._AfterDump, path, None)
            except OSError as e:
                wx.CallAfter(self._AfterDump, None, str(e))

        Thread(target=worker, daemon=True).start()

    def _AfterDump(self, path, err):
        if err:
            self._SetStatus("Memory dump failed")
            wx.MessageBox(err, "Process Tree", wx.OK | wx.ICON_ERROR)
        else:
            self._SetStatus(f"Memory dumped to {path}")

    def _SetStatus(self, message):
        getMainFrame = getattr(self.startPanel, "GetMainFrame", None)
        mainFrame = getMainFrame() if getMainFrame else None
        if mainFrame and getattr(mainFrame, "statusBar", None):
            mainFrame.statusBar.SetMessage(message)

    def OnClose(self, event):
        self.timer.Stop()
        self.startPanel.processTreeWindow = None
        self.Destroy()
