import logging
import re
import threading
from collections import namedtuple
from typing import List, Optional, Tuple

import wx
from .debug_graph import HAS_GRAPHVIZ

log = logging.getLogger(__name__)

COLOR_LIGHT_YELLOW = wx.Colour(255, 255, 150)
COLOR_LIGHT_RED = wx.Colour(255, 102, 102)
MAX_IDLE = 1

DecodedInstruction = namedtuple("DecodedInstruction", ["address", "bytes", "text"])


def IsValidHex(s):
    if len(s) < 8 or (s.startswith("0x") or s.startswith("0X")) and len(s) < 10:
        return False

    pattern = r"^(0[xX])?[0-9a-fA-F]+$"
    return bool(re.match(pattern, s))


class DisassemblyListCtrl(wx.ListCtrl):
    def __init__(self, parent):
        super().__init__(parent, style=wx.LC_REPORT)
        self.parent = parent
        self.lastTipRow = None
        self.InsertColumn(0, "Address", width=150)
        self.InsertColumn(1, "Hex bytes", width=180)
        self.InsertColumn(2, "Disassembly", width=400)
        self.pageMap: List[Tuple[int, int, int]] = []
        self.decodeCache: List[DecodedInstruction] = []
        self.cacheLock = threading.Lock()
        self.Bind(wx.EVT_CONTEXT_MENU, self.OnContextMenu)
        self.Bind(wx.EVT_MOTION, self.OnMouseOver)

    def LoadPageMap(self, data: str):
        if not data:
            return

        self.pageMap.clear()
        for entry in data.split("|"):
            if not entry:
                continue

            try:
                base, size, protect = entry.split(",")
                baseAddr = int(base, 16)
                regionSize = int(size)
                protect = int(protect, 16)
                self.pageMap.append((baseAddr, regionSize, protect))
            except (ValueError, AttributeError) as e:
                log.error("[DEBUG CONSOLE] Failed to parse entry '%s': %s", entry, e)
                continue

        self.pageMap.sort(key=lambda x: x[0])

    def FindPage(self, addr: int) -> Optional[Tuple[int, int, int]]:
        for base, size, prot in self.pageMap:
            if base <= addr < base + size:
                return base, size, prot

        # log.warning("[DEBUG CONSOLE] Address: 0x%x not in page map, fetching update page map", addr)
        return None

    def SetInstructions(self, insts: List[DecodedInstruction], append: bool = False):
        self.Freeze()
        try:
            with self.cacheLock:
                if not append:
                    self.decodeCache = []
                    self.DeleteAllItems()

                startRow = len(self.decodeCache)
                self.decodeCache.extend(insts)
                for offset, inst in enumerate(insts):
                    row = startRow + offset
                    row = self.InsertItem(row, f"{inst.address:016X}")
                    self.SetItem(row, 1, inst.bytes.upper())
                    self.SetItem(row, 2, inst.text)
                    mnemonic = inst.text.split()[0].lower()
                    if mnemonic == "call":
                        self.SetItemTextColour(row, wx.BLUE)
                    elif mnemonic in ("jmp", "je", "jne", "jg", "jl"):
                        self.SetItemTextColour(row, wx.GREEN)
        finally:
            self.Thaw()

        if append:
            self.Refresh()
        else:
            row = self.GetCipRow()
            if row != -1:
                self.HighlightIp(row)

    def GetCipRow(self, cip=None):
        row = -1
        if not cip:
            cip = self.parent.cip
        if cip is None:
            return

        with self.cacheLock:
            for i, inst in enumerate(self.decodeCache):
                if inst.address == cip:
                    row = i
                    break

        return row

    def GetInstructionRow(self, addr: int):
        row = -1
        with self.cacheLock:
            for i, inst in enumerate(self.decodeCache):
                if inst.address == addr:
                    row = i
                    break
        return row

    def HighlightIp(self, row):
        if row >= 0:
            for i in range(self.GetItemCount()):
                if self.GetItemBackgroundColour(i) != COLOR_LIGHT_YELLOW:
                    self.SetItemBackgroundColour(i, wx.Colour(wx.WHITE))

            self.SetItemBackgroundColour(row, wx.Colour(wx.CYAN))
            self.CenterRow(row)
        else:
            log.warning("[DEBUG CONSOLE] Instruction %#x not found in disassembly", self.parent.cip)

        self.Refresh()

    def CenterRow(self, row):
        """Center the specified row in the view."""
        visRows = self.GetCountPerPage()
        if visRows <= 0:
            rowH = 15
            rect = self.GetItemRect(0, wx.LIST_RECT_BOUNDS)
            rowH = rect.height if rect and rect.height > 0 else rowH
            clientH = self.GetClientSize().height
            visRows = clientH // rowH

        visRows = min(visRows, len(self.decodeCache))
        if visRows <= 0:
            visRows = 15

        anchor = max(0, row + (visRows // 2))
        maxTop = max(0, len(self.decodeCache) - visRows)
        anchor = min(anchor, maxTop)

        self.EnsureVisible(row)
        self.EnsureVisible(anchor)

    def TopRow(self, row):
        """Scroll the specified row so it becomes the topmost visible row."""
        visRows = self.GetCountPerPage()
        if visRows <= 0:
            rowH = 15
            rect = self.GetItemRect(0, wx.LIST_RECT_BOUNDS)
            if rect and rect.height > 0:
                rowH = rect.height
            visRows = self.GetClientSize().height // rowH

        maxTop = max(0, len(self.decodeCache) - visRows)
        row = max(0, min(row, maxTop))

        self.EnsureVisible(row)
        row = row + visRows - 1
        if row < self.GetItemCount():
            self.EnsureVisible(row)

    def OnContextMenu(self, event):
        pos = event.GetPosition()
        pos = self.ScreenToClient(pos)
        row, flags = self.HitTest(pos)
        if row == wx.NOT_FOUND:
            return

        menu = wx.Menu()
        miCopy = menu.Append(wx.ID_ANY, "Copy")
        miGoTo = menu.Append(wx.ID_ANY, "Go To")
        miGoToSelected = menu.Append(wx.ID_ANY, "Go To Selected Address")
        miGoToCIP = menu.Append(wx.ID_ANY, "Go To EIP/RIP")
        menu.AppendSeparator()
        miStepInto = menu.Append(wx.ID_ANY, "Step Into")
        miStepOver = menu.Append(wx.ID_ANY, "Step Over")
        miStepOut = menu.Append(wx.ID_ANY, "Step Out")
        miRunUntil = menu.Append(wx.ID_ANY, "Run Until")
        menu.AppendSeparator()
        bpMenu = wx.Menu()
        for slot in ("Next", "0", "1", "2", "3"):
            bpId = wx.NewIdRef()
            bpMenu.Append(bpId, slot)
            self.Bind(wx.EVT_MENU, lambda evt, s=slot: self.OnSetBreakpoint(evt, row, s), id=bpId)

        menu.AppendSubMenu(bpMenu, "Set Breakpoint")
        miDeleteBreakpoint = menu.Append(wx.ID_ANY, "Delete Breakpoint")
        menu.AppendSeparator()
        miGraphText = "Flow Graph"
        if not HAS_GRAPHVIZ:
            miGraphText += ": Install Graphviz"
        miGraph = menu.Append(wx.ID_ANY, miGraphText)
        miGraph.Enable(HAS_GRAPHVIZ)

        self.Bind(wx.EVT_MENU, self.OnCopy, miCopy)
        self.Bind(wx.EVT_MENU, self.OnGoTo, miGoTo)
        self.Bind(wx.EVT_MENU, self.OnGoToCIP, miGoToCIP)
        self.Bind(wx.EVT_MENU, self.OnStepInto, miStepInto)
        self.Bind(wx.EVT_MENU, self.OnStepOver, miStepOver)
        self.Bind(wx.EVT_MENU, self.OnStepOut, miStepOut)
        self.Bind(wx.EVT_MENU, lambda e: self.OnGoToSelected(row), miGoToSelected)
        self.Bind(wx.EVT_MENU, lambda e: self.OnRunUntil(row), miRunUntil)
        self.Bind(wx.EVT_MENU, lambda e: self.OnDeleteBreakpoint(row), miDeleteBreakpoint)
        self.Bind(wx.EVT_MENU, lambda e: self.parent.ShowFlowGraph(), miGraph)
        self.PopupMenu(menu, pos)
        menu.Destroy()

    def OnCopy(self, event):
        rows = []
        row = -1
        while True:
            row = self.GetNextItem(row, wx.LIST_NEXT_ALL, wx.LIST_STATE_SELECTED)
            if row == -1:
                break

            rows.append(row)

        if not rows:
            return

        lines = []
        for row in rows:
            cols = []
            for col in range(self.GetColumnCount()):
                cols.append(self.GetItemText(row, col))

            lines.append("\t".join(cols))

        text = "\n".join(lines)
        clipboard = wx.TheClipboard
        if clipboard.Open():
            try:
                clipboard.SetData(wx.TextDataObject(text))
                clipboard.Flush()
            except Exception as e:
                wx.MessageBox(f"Failed to copy to clipboard: {e}", "Error", wx.OK | wx.ICON_ERROR)
            finally:
                clipboard.Close()

    def OnGoTo(self, event):
        dialog = wx.TextEntryDialog(self, "Enter hex address (e.g., 0x12345678) or Register:", "Go To Address")
        if dialog.ShowModal() == wx.ID_OK:
            entry = dialog.GetValue().strip()
            target = None
            regsText = self.parent.regsDisplay.GetValue()
            reg = entry.upper()
            m = re.search(rf"\b{reg}\b\s*:\s*([0-9A-Fa-f]+)", regsText)
            if m:
                target = m.group(1)

            if target is None:
                target = entry.lower()
                if not target.startswith("0x"):
                    target = "0x" + target

                try:
                    int(target, 16)
                except ValueError:
                    wx.MessageBox(f"Invalid hex address: {entry}", "Error", wx.OK | wx.ICON_ERROR)
                    dialog.Destroy()
                    return

            try:
                row = self.GoToInstruction(target)
                if row == wx.NOT_FOUND:
                    wx.MessageBox(f"Instruction address not found: {entry}", "Warning", wx.OK | wx.ICON_WARNING)
            except Exception as e:
                wx.MessageBox(f"Invalid register or hex address: {entry}", "Error", wx.OK | wx.ICON_ERROR)

        dialog.Destroy()

    def OnGoToSelected(self, row):
        addrStr = self.GetItemText(row, 0).strip()
        try:
            self.GoToInstruction(addrStr)
        except ValueError as e:
            wx.MessageBox(f"Invalid selected address: {addrStr}", "Error", wx.OK | wx.ICON_ERROR)

    def OnGoToCIP(self, event):
        row = self.GetCipRow(self.parent.cip)
        self.HighlightIp(row)

    def OnStepInto(self, event):
        self.parent.SendCommand("S")

    def OnStepOver(self, event):
        self.parent.SendCommand("O")

    def OnStepOut(self, event):
        self.parent.SendCommand("U")

    def OnRunUntil(self, row):
        addrStr = self.GetItemText(row, 0).strip()
        try:
            addr = int(addrStr, 16)
            payload = f"{addr:#X}"
            self.parent.SendCommand("T", payload)
        except ValueError as e:
            wx.MessageBox(f"Invalid address for Run Until: {addrStr}", "Error", wx.OK | wx.ICON_ERROR)

    def OnSetBreakpoint(self, event, row, slot):
        addrStr = self.GetItemText(row, 0).strip()
        try:
            addr = int(addrStr, 16)
            payload = f"{slot.lower()}|{addr:#X}"
            self.parent.SendCommand("B", payload)
        except ValueError as e:
            wx.MessageBox(f"Invalid address for Set Breakpoint Until: {addrStr}", "Error", wx.OK | wx.ICON_ERROR)

    def OnDeleteBreakpoint(self, row):
        addrStr = self.GetItemText(row, 0).strip()
        try:
            addr = int(addrStr, 16)
            payload = f"{addr:#X}"
            self.parent.SendCommand("D", payload)
        except ValueError as e:
            wx.MessageBox(f"Invalid address forDelete Breakpoint: {addrStr}", "Error", wx.OK | wx.ICON_ERROR)

    def ClearBpBackground(self, addr):
        row = self.GetInstructionRow(addr)
        self.SetItemBackgroundColour(row, wx.Colour(wx.WHITE))
        self.Refresh()

    def SetBpBackground(self, addr):
        row = self.GetInstructionRow(addr)
        self.SetItemBackgroundColour(row, wx.Colour(COLOR_LIGHT_RED))
        self.Refresh()

    def GoToInstruction(self, addr):
        addr = int(addr, 16)
        row = self.GetInstructionRow(addr)
        self.CenterRow(row)
        self.Select(row)
        self.Focus(row)
        self.Refresh()
        return row

    def OnMouseOver(self, event):
        x, y = event.GetPosition()
        row, flags = self.HitTest(wx.Point(x, y))
        if row == wx.NOT_FOUND or row == self.lastTipRow:
            if row == wx.NOT_FOUND:
                self.SetToolTip(None)
                self.lastTipRow = None

            return event.Skip()

        inst = self.GetItemText(row, 2)
        m = re.search(r"\[([A-Z]+)\s*\+\s*0x([0-9A-Fa-f]+)\]", inst)
        if not m:
            self.SetToolTip(None)
            self.lastTipRow = None
            return event.Skip()

        regName, offHex = m.group(1), m.group(2)
        regsText = self.parent.regsDisplay.GetValue()
        rm = re.search(rf"{regName}:\s*([0-9A-Fa-f]+)", regsText)
        if not rm:
            self.SetToolTip(None)
            self.lastTipRow = None
            return event.Skip()

        regVal = int(rm.group(1), 16)
        addr = regVal + int(offHex, 16)
        addrStr = f"{addr:#x}"
        self.SetToolTip(addrStr)
        if wx.TheClipboard.Open():
            try:
                wx.TheClipboard.SetData(wx.TextDataObject(addrStr))
            finally:
                wx.TheClipboard.Close()

        self.lastTipRow = row
        return event.Skip()


class RegsTextCtrl(wx.TextCtrl):
    def __init__(self, parent, style):
        """TextCtrl subclass"""
        super().__init__(parent, style=style)
        self.parent = parent
        self.Bind(wx.EVT_CONTEXT_MENU, self.OnContextMenu)

    def OnContextMenu(self, event):
        menu = wx.Menu()
        miCopy = menu.Append(wx.ID_ANY, "Copy")
        miDumpAddress = menu.Append(wx.ID_ANY, "Dump Memory Address")
        miFollowAddress = menu.Append(wx.ID_ANY, "Follow Address")
        menu.AppendSeparator()
        miClearZeroFlag = menu.Append(wx.ID_ANY, "Clear Zero Flag")
        miSetZeroFlag = menu.Append(wx.ID_ANY, "Set Zero Flag")
        miFlipZeroFlag = menu.Append(wx.ID_ANY, "Flip Zero Flag")
        menu.AppendSeparator()
        miClearSignFlag = menu.Append(wx.ID_ANY, "Clear Sign Flag")
        miSetSignFlag = menu.Append(wx.ID_ANY, "Set Sign Flag")
        miFlipSignFlag = menu.Append(wx.ID_ANY, "Flip Sign Flag")
        menu.AppendSeparator()
        miClearCarryFlag = menu.Append(wx.ID_ANY, "Clear Carry Flag")
        miSetCarryFlag = menu.Append(wx.ID_ANY, "Set Carry Flag")
        miFlipCarryFlag = menu.Append(wx.ID_ANY, "Flip Carry Flag")

        self.Bind(wx.EVT_MENU, self.OnDumpAddress, miDumpAddress)
        self.Bind(wx.EVT_MENU, self.OnFollowAddress, miFollowAddress)
        self.Bind(wx.EVT_MENU, self.ClearZeroFlag, miClearZeroFlag)
        self.Bind(wx.EVT_MENU, self.SetZeroFlag, miSetZeroFlag)
        self.Bind(wx.EVT_MENU, self.FlipZeroFlag, miFlipZeroFlag)
        self.Bind(wx.EVT_MENU, self.ClearSignFlag, miClearSignFlag)
        self.Bind(wx.EVT_MENU, self.SetSignFlag, miSetSignFlag)
        self.Bind(wx.EVT_MENU, self.FlipSignFlag, miFlipSignFlag)
        self.Bind(wx.EVT_MENU, self.ClearCarryFlag, miClearCarryFlag)
        self.Bind(wx.EVT_MENU, self.SetCarryFlag, miSetCarryFlag)
        self.Bind(wx.EVT_MENU, self.FlipCarryFlag, miFlipCarryFlag)
        self.Bind(wx.EVT_MENU, self.OnCopy, miCopy)

        pos = event.GetPosition()
        pos = self.ScreenToClient(pos)
        self.PopupMenu(menu, pos)
        menu.Destroy()

    def OnDumpAddress(self, event):
        sel = self.GetStringSelection().strip()
        if sel:
            self.parent.memAddressInput.SetValue(sel)
            evt = wx.CommandEvent(wx.EVT_TEXT_ENTER.typeId, self.parent.memAddressInput.GetId())
            self.parent.OnAddressEnter(evt)

    def OnFollowAddress(self, event):
        addrStr = self.GetStringSelection().strip()
        if addrStr and IsValidHex(addrStr):
            self.parent.disassemblyConsole.GoToInstruction(addrStr)

    def OnCopy(self, event):
        text = self.GetStringSelection().strip()
        clipboard = wx.TheClipboard
        if clipboard.Open():
            try:
                clipboard.SetData(wx.TextDataObject(text))
                clipboard.Flush()
            except Exception as e:
                wx.MessageBox(f"Failed to copy to clipboard: {e}", "Error", wx.OK | wx.ICON_ERROR)
            finally:
                clipboard.Close()

    def ClearZeroFlag(self, event):
        self.FlagCommand("ClearZeroFlag")

    def SetZeroFlag(self, event):
        self.FlagCommand("SetZeroFlag")

    def FlipZeroFlag(self, event):
        self.FlagCommand("FlipZeroFlag")

    def ClearSignFlag(self, event):
        self.FlagCommand("ClearSignFlag")

    def SetSignFlag(self, event):
        self.FlagCommand("SetSignFlag")

    def FlipSignFlag(self, event):
        self.FlagCommand("FlipSignFlag")

    def ClearCarryFlag(self, event):
        self.FlagCommand("ClearCarryFlag")

    def SetCarryFlag(self, event):
        self.FlagCommand("SetCarryFlag")

    def FlipCarryFlag(self, event):
        self.FlagCommand("FlipCarryFlag")

    def FlagCommand(self, cmd):
        self.parent.SendCommand("E", cmd)
        self.parent.SendCommand("K")


class StackListCtrl(wx.ListCtrl):
    def __init__(self, parent):
        super().__init__(parent, style=wx.LC_REPORT)
        self.parent = parent
        self.spVal = None
        self.InsertColumn(0, "Address", width=170)
        self.InsertColumn(1, "Value", width=170)
        self.InsertColumn(2, "", width=70)
        self.data = []
        self.Bind(wx.EVT_CONTEXT_MENU, self.OnContextMenu)

    def UpdateData(self, data):
        """Populate the list with rows and highlight."""
        rows = []
        for line in data.splitlines():
            parts = [p.strip() for p in line.split(",", 1)]

            if len(parts) < 2:
                continue

            addr, val = parts[0], parts[1]
            rows.append((addr, val))

        regsText = self.parent.regsDisplay.GetValue()
        m = re.search(r"\b([ER]SP):\s*([0-9A-Fa-f]+)", regsText)
        self.spVal = m.group(2) if m else None
        row = len(rows) // 2
        if self.spVal:
            for i, (addr, _) in enumerate(rows):
                if addr.lower() == self.spVal.lower():
                    row = i
                    break

        self.DeleteAllItems()
        self.data = rows

        for i, (addr, val) in enumerate(rows):
            self.InsertItem(i, str(addr))
            self.SetItem(i, 1, str(val))
            self.SetItem(i, 2, "")

            if i == row:
                self.SetItemBackgroundColour(i, COLOR_LIGHT_YELLOW)

        self.Refresh()
        self.CenterRow(row)

    @staticmethod
    def GetAscii(dataBytes) -> str:
        """Inspect an 8-byte qword for printable ASCII; return '.' for non-printable."""
        buf = dataBytes[:8].ljust(8, b"\x00")
        asciiStr = "".join(chr(b) if 32 <= b < 127 else "." for b in buf)
        return asciiStr

    def OnContextMenu(self, event):
        pos = event.GetPosition()
        pos = self.ScreenToClient(pos)
        row, flags = self.HitTest(pos)
        if row == wx.NOT_FOUND:
            return

        menu = wx.Menu()
        miCopy = menu.Append(wx.ID_ANY, "Copy")
        miFollowAddr = menu.Append(wx.ID_ANY, "Dump Address")
        miFollowVal = menu.Append(wx.ID_ANY, "Dump Value")

        self.Bind(wx.EVT_MENU, self.OnCopy, miCopy)
        self.Bind(
            wx.EVT_MENU,
            lambda e, r=row: (
                self.parent.memAddressInput.SetValue(self.data[r][0]),
                self.parent.OnAddressEnter(wx.CommandEvent(wx.EVT_TEXT_ENTER.typeId, self.parent.memAddressInput.GetId())),
            ),
            miFollowAddr,
        )
        self.Bind(
            wx.EVT_MENU,
            lambda e, r=row: (
                self.parent.memAddressInput.SetValue(self.data[r][1]),
                self.parent.OnAddressEnter(wx.CommandEvent(wx.EVT_TEXT_ENTER.typeId, self.parent.memAddressInput.GetId())),
            ),
            miFollowVal,
        )

        self.PopupMenu(menu, pos)
        menu.Destroy()

    def OnCopy(self, event):
        rows = []
        row = -1
        while True:
            row = self.GetNextItem(row, wx.LIST_NEXT_ALL, wx.LIST_STATE_SELECTED)
            if row == -1:
                break

            rows.append(row)

        if not rows:
            return

        lines = []
        for row in rows:
            cols = []
            for col in range(self.GetColumnCount()):
                cols.append(self.GetItemText(row, col))

            lines.append("\t".join(cols))

        text = "\n".join(lines)
        clipboard = wx.TheClipboard
        if clipboard.Open():
            try:
                clipboard.SetData(wx.TextDataObject(text))
                clipboard.Flush()
            except Exception as e:
                wx.MessageBox(f"Failed to copy to clipboard: {e}", "Error", wx.OK | wx.ICON_ERROR)
            finally:
                clipboard.Close()

    def CenterRow(self, row):
        """Center the specified row in the view."""
        if not self.data or row < 0 or row >= len(self.data):
            return

        visRows = self.GetCountPerPage()
        if visRows <= 0:
            rowH = 15
            rect = self.GetItemRect(0, wx.LIST_RECT_BOUNDS)
            rowH = rect.height if rect and rect.height > 0 else rowH
            clientH = self.GetClientSize().height
            visRows = clientH // rowH

        visRows = min(visRows, len(self.data))
        if visRows <= 0:
            visRows = 15

        anchor = max(0, row + (visRows // 2))
        maxTop = max(0, len(self.data) - visRows)
        anchor = min(anchor, maxTop)

        self.EnsureVisible(row)
        self.EnsureVisible(anchor)


class MemDumpListCtrl(wx.ListCtrl):
    def __init__(self, parent):
        super().__init__(parent, style=wx.LC_REPORT)
        self.InsertColumn(0, "Address", width=170)
        self.InsertColumn(1, "Hex Dump", width=400)
        self.InsertColumn(2, "Ascii", width=150)
        self.data = []
        self.Bind(wx.EVT_CONTEXT_MENU, self.OnContextMenu)

    def UpdateData(self, data):
        """Populate the list control from a string of lines."""
        self.DeleteAllItems()
        self.data.clear()

        for i, line in enumerate(data.splitlines()):
            parts = [p.strip() for p in line.split(",", 1)]
            if not parts:
                continue

            addr = parts[0]
            hexStr = parts[1] if len(parts) > 1 else ""
            asciiChars = []
            for byteToken in hexStr.split():
                try:
                    val = int(byteToken, 16)
                    asciiChars.append(chr(val) if 32 <= val < 127 else ".")
                except ValueError:
                    asciiChars.append(".")

            asciiStr = "".join(asciiChars)
            self.data.append((addr, hexStr, asciiStr))
            row = self.InsertItem(i, addr)
            self.SetItem(row, 1, hexStr)
            self.SetItem(row, 2, asciiStr)

    def GetFirstHexAddress(self):
        """Return the address string from the first row, or None if empty."""
        return self.data[0][0] if self.data else None

    def OnContextMenu(self, event):
        pos = event.GetPosition()
        pos = self.ScreenToClient(pos)
        menu = wx.Menu()
        miCopy = menu.Append(wx.ID_ANY, "Copy")
        self.Bind(wx.EVT_MENU, self.OnCopy, miCopy)
        self.PopupMenu(menu, pos)
        menu.Destroy()

    def OnCopy(self, event):
        rows = []
        row = -1
        while True:
            row = self.GetNextItem(row, wx.LIST_NEXT_ALL, wx.LIST_STATE_SELECTED)
            if row == -1:
                break

            rows.append(row)

        if not rows:
            return

        lines = []
        for row in rows:
            cols = []
            for col in range(self.GetColumnCount()):
                cols.append(self.GetItemText(row, col))

            lines.append("\t".join(cols))

        text = "\n".join(lines)
        clipboard = wx.TheClipboard
        if clipboard.Open():
            try:
                clipboard.SetData(wx.TextDataObject(text))
                clipboard.Flush()
            except Exception as e:
                wx.MessageBox(f"Failed to copy to clipboard: {e}", "Error", wx.OK | wx.ICON_ERROR)
            finally:
                clipboard.Close()


class ThreadListCtrl(wx.ListCtrl):
    """List control to display threads with columns: TID, Start Address."""

    def __init__(self, parent):
        super().__init__(parent, style=wx.LC_REPORT | wx.LC_SINGLE_SEL)
        self.data: List[Tuple[str, str]] = []
        self.InsertColumn(0, "TID", width=60)
        self.InsertColumn(1, "Start Address", width=160)

    def UpdateData(self, threadEntries: List[Tuple[str, str]]):
        """Populate the list with thread info: (tid, start address)."""
        self.DeleteAllItems()
        self.data = threadEntries
        for i, (tid, addr) in enumerate(threadEntries):
            row = self.InsertItem(i, tid)
            self.SetItem(row, 1, addr)
            if i == 0:
                font = self.GetFont()
                boldFont = wx.Font(font.GetPointSize(), font.GetFamily(), font.GetStyle(), wx.FONTWEIGHT_BOLD)
                self.SetItemFont(row, boldFont)


class BreakpointsListCtrl(wx.ListCtrl):
    """List control to display breakpoints with columns: dr, Address."""

    def __init__(self, parent):
        super().__init__(parent, style=wx.LC_REPORT | wx.LC_SINGLE_SEL)
        self.parent = parent
        self.data: List[Tuple[str, str]] = []
        self.InsertColumn(0, "DR", width=40)
        self.InsertColumn(1, "Address", width=160)
        self.Bind(wx.EVT_CONTEXT_MENU, self.OnContextMenu)

    def UpdateData(self, bps: List[Tuple[str, str]]):
        """Populate the list with thread info: (dr, address)."""
        for i in range(self.GetItemCount()):
            addr = self.GetItemText(i, 1).strip()
            self.parent.disassemblyConsole.SetBpBackground(addr)

        self.DeleteAllItems()
        self.data = bps
        for i, (dr, addr) in enumerate(bps):
            row = self.InsertItem(i, dr)
            self.SetItem(row, 1, addr)
            self.parent.disassemblyConsole.SetBpBackground(addr)

    def OnContextMenu(self, event):
        pos = event.GetPosition()
        pos = self.ScreenToClient(pos)
        row, flags = self.HitTest(pos)
        if row == wx.NOT_FOUND:
            return

        menu = wx.Menu()
        miDeleteBreakpoint = menu.Append(wx.ID_ANY, "Delete Breakpoint")
        menu.AppendSeparator()
        miFollowBreakpoint = menu.Append(wx.ID_ANY, "Follow Address")

        self.Bind(wx.EVT_MENU, lambda e: self.OnDeleteBreakpoint(row), miDeleteBreakpoint)
        self.Bind(wx.EVT_MENU, lambda e: self.OnFollowBreakpoint(row), miFollowBreakpoint)
        self.PopupMenu(menu, pos)
        menu.Destroy()

    def OnDeleteBreakpoint(self, row):
        addrStr = self.GetItemText(row, 1).strip()
        try:
            addr = int(addrStr, 16)
            payload = f"{addr:#X}"
            self.parent.SendCommand("D", payload)
        except ValueError as e:
            log.error("[DEBUG CONSOLE] Invalid address for Delete Breakpoint: %s (%s)", addrStr, e)
            wx.MessageBox(f"Invalid address forDelete Breakpoint: {addrStr}", "Error", wx.OK | wx.ICON_ERROR)

    def OnFollowBreakpoint(self, row):
        addrStr = self.GetItemText(row, 1).strip()
        self.parent.disassemblyConsole.GoToInstruction(addrStr)


class ModulesListCtrl(wx.ListCtrl):
    """List control to display modules with columns: Address, Name."""

    def __init__(self, parent):
        super().__init__(parent, style=wx.LC_REPORT | wx.LC_SINGLE_SEL)
        self.parent = parent
        self.lastHoverRow = None
        self.InsertColumn(0, "Address", width=160)
        self.InsertColumn(1, "Size", width=80)
        self.InsertColumn(2, "Name", width=160)
        self.InsertColumn(3, "Path", width=160)
        self.Bind(wx.EVT_CONTEXT_MENU, self.OnContextMenu)

    def UpdateData(self, modules: List[Tuple[str, str, str, str]]):
        """Populate the list"""
        self.DeleteAllItems()
        for i, (addr, size, name, path) in enumerate(modules):
            row = self.InsertItem(i, addr)
            self.SetItem(row, 1, size)
            self.SetItem(row, 2, name)
            self.SetItem(row, 3, path)

    def OnContextMenu(self, event):
        pos = event.GetPosition()
        pos = self.ScreenToClient(pos)
        row, _ = self.HitTest(pos)
        if row == wx.NOT_FOUND:
            return

        menu = wx.Menu()
        mi = menu.Append(wx.ID_ANY, "Symbols")
        self.Bind(wx.EVT_MENU, lambda e: self.OnShowSymbols(row), mi)
        self.PopupMenu(menu, pos)
        menu.Destroy()

    def OnShowSymbols(self, row):
        modName = self.GetItemText(row, 2)
        matches = []
        for addr, full in self.parent.symbols.items():
            if full.startswith(modName + "!"):
                _, sym = full.split("!", 1)
                matches.append((sym, addr))

        if not matches:
            wx.MessageBox(f"No symbols for module {modName}", "Info", wx.OK|wx.ICON_INFORMATION)
            return

        dlg = SymbolsDialog(self, modName, matches)
        dlg.ShowModal()
        dlg.Destroy()


class SymbolsDialog(wx.Dialog):
    def __init__(self, parent, mod_name, symbols):
        super().__init__(
            parent, title=f"Symbols for {mod_name}", size=wx.Size(500, 600), style=wx.DEFAULT_DIALOG_STYLE | wx.RESIZE_BORDER
        )
        sizer = wx.BoxSizer(wx.VERTICAL)

        listCtrl = wx.ListCtrl(self, style=wx.LC_REPORT | wx.BORDER_SUNKEN)
        listCtrl.InsertColumn(0, "Address", width=200)
        listCtrl.InsertColumn(1, "Name", width=300)
        for i, (symName, addr) in enumerate(symbols):
            row = listCtrl.InsertItem(i, f"{int(addr):#x}")
            listCtrl.SetItem(row, 1, symName)

        sizer.Add(listCtrl, 1, wx.EXPAND | wx.ALL, 10)
        btn = wx.Button(self, wx.ID_OK, "Close")
        sizer.Add(btn, 0, wx.ALIGN_CENTER | wx.ALL, 10)
        self.SetSizer(sizer)
        self.Layout()
