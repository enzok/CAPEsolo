import ast
import logging
import operator
import re
import threading
from collections import namedtuple
from pathlib import Path

import wx

from CAPEsolo.capelib.cmdconsts import *
from CAPEsolo.capelib.page_cache import CommonPrefixLength, FindRegion

from .patch_dialog import ConfirmPatchDialog, PatchDialog, PatchHistoryDialog
from .patch_models import PatchEntry
from .search_dialog import SearchDialog
from .theme import (
    ACCENT_CALL,
    ACCENT_ERROR,
    ACCENT_GREEN,
    ACCENT_JUMP,
    ACCENT_ORANGE,
    BG_INPUT,
)

log = logging.getLogger(__name__)

# Mirrors debug_console.TAG_DUMP; importing it would be circular.
TAG_DUMP = "DUMP"
# Breakpoint types as sent to capemon, and how they read in the Breakpoints pane.
BP_EXEC, BP_WRITE, BP_READWRITE = "x", "w", "rw"
BP_TYPE_LABELS = {BP_EXEC: "exec", BP_WRITE: "write", BP_READWRITE: "r/w"}
BP_SIZES = (1, 2, 4, 8)
COLOR_LIGHT_YELLOW = ACCENT_ORANGE
COLOR_LIGHT_RED = ACCENT_ERROR
MAX_IDLE = 1

DecodedInstruction = namedtuple("DecodedInstruction", ["address", "bytes", "text"])

def IsValidHexAddress(s: str) -> bool:
    try:
        if not s.lower().startswith("0x"):
            s = "0x" + s

        value = int(s, 16)
    except ValueError:
        return False

    return value > 0x1000

def SetClipboard(text: str):
    clipboard = wx.TheClipboard
    textObj = wx.TextDataObject(text)
    if clipboard.Open():
        try:
            wx.TheClipboard.Clear()
            clipboard.SetData(textObj)
            clipboard.Flush()
        finally:
            clipboard.Close()


def GetClipboardText():
    data = wx.TextDataObject()
    if wx.TheClipboard.Open():
        try:
            if wx.TheClipboard.IsSupported(wx.DataFormat(wx.DF_TEXT)):
                wx.TheClipboard.GetData(data)
                return data.GetText()
        finally:
            wx.TheClipboard.Close()

    return ""


class DisassemblyListCtrl(wx.ListCtrl):
    def __init__(self, parent, console=None):
        super().__init__(parent, style=wx.LC_REPORT)
        # `console` separates the wx parent from the ConsolePanel these controls call
        # back into: with the splitter layout the wx parent is a splitter pane.
        self.parent = console or parent
        self.lastTipRow = None
        self.InsertColumn(0, "Address", width=150)
        self.InsertColumn(1, "Hex bytes", width=180)
        self.InsertColumn(2, "Disassembly", width=400)
        self.pageMap: list[tuple[int, int, int]] = []
        self.decodeCache: list[DecodedInstruction] = []
        self.cacheLock = threading.Lock()
        self.backHistory: list[int] = []
        self.resolveAllRefsStatus = True
        self.fontItalic = wx.Font(10, wx.FONTFAMILY_MODERN, wx.FONTSTYLE_ITALIC, wx.FONTWEIGHT_NORMAL)
        # Rows are rebuilt on every break, which drops their colours, so breakpoint addresses
        # are kept here and re-applied. cipRow is the one row holding the CIP highlight.
        self.bpAddrs: set[int] = set()
        self.cipRow = None
        self.Bind(wx.EVT_CONTEXT_MENU, self.OnContextMenu)
        self.Bind(wx.EVT_MOTION, self.OnOperandHover)
        self.Bind(wx.EVT_KEY_DOWN, self.OnKeyDown)

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

    def FindPage(self, addr: int) -> tuple[int, int, int] | None:
        return FindRegion(self.pageMap, addr)

    def SetInstructions(self, insts: list[DecodedInstruction]):
        """Render `insts`, reusing every row the new stream shares with the old one.

        A single step normally decodes the same instructions split at a different CIP, so the
        shared prefix is the whole list and no row is touched at all. The previous version
        called DeleteAllItems and re-inserted every row on every break.
        """
        self.Freeze()
        try:
            with self.cacheLock:
                firstChanged = CommonPrefixLength(self.decodeCache, insts)
                self.decodeCache = list(insts)
                for row in range(self.GetItemCount() - 1, firstChanged - 1, -1):
                    self.DeleteItem(row)

                if self.cipRow is not None and self.cipRow >= firstChanged:
                    self.cipRow = None

                for row in range(firstChanged, len(self.decodeCache)):
                    self._InsertRow(row, self.decodeCache[row])
        finally:
            self.Thaw()

        self.Refresh()
        self.HighlightCip(self.GetCipRow())

    def _InsertRow(self, row: int, inst: DecodedInstruction):
        row = self.InsertItem(row, f"{inst.address:016X}")
        self.SetItem(row, 1, inst.bytes.upper())
        self.SetItem(row, 2, inst.text)
        mnemonic = inst.text.split()[0].lower()
        if mnemonic == "call":
            self.SetItemTextColour(row, ACCENT_CALL)
        elif mnemonic in ("jmp", "je", "jne", "jg", "jl"):
            self.SetItemTextColour(row, ACCENT_JUMP)

        if inst.address in self.parent.patchHistoryByAddr:
            self.SetItemFont(row, self.fontItalic)

        if inst.address in self.bpAddrs:
            self.SetItemBackgroundColour(row, COLOR_LIGHT_RED)

    def GetCipRow(self, cip=None):
        row = -1
        if cip is None:
            cip = self.parent.cip
        if cip is None:
            return row

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

    def ClearHighlight(self):
        """Repaint only the previously highlighted row; the rest were never recoloured."""
        if self.cipRow is None:
            return

        if 0 <= self.cipRow < self.GetItemCount():
            with self.cacheLock:
                inst = self.decodeCache[self.cipRow] if self.cipRow < len(self.decodeCache) else None

            bp = inst is not None and inst.address in self.bpAddrs
            self.SetItemBackgroundColour(self.cipRow, COLOR_LIGHT_RED if bp else BG_INPUT)

        self.cipRow = None

    def HighlightCip(self, row):
        self.ClearHighlight()
        if row < 0:
            cip = self.parent.cip
            log.warning("[DEBUG CONSOLE] Instruction %s not found in disassembly", f"{cip:#x}" if cip else "(unknown)")
            self.Refresh()
            return

        self.cipRow = row
        self.SetItemBackgroundColour(row, ACCENT_GREEN)
        self.CenterRow(row)
        self.Refresh()

    def CenterRow(self, row):
        """Center the specified row in the view with a single scroll."""
        count = self.GetItemCount()
        if row < 0 or count == 0:
            return

        visRows = self.GetCountPerPage()
        if visRows <= 0:
            self.EnsureVisible(row)
            return

        # Two EnsureVisible calls scroll twice, which shows as a jump on every step.
        target = max(0, min(row - visRows // 2, count - visRows))
        self.ScrollLines(target - self.GetTopItem())
        if not self.IsVisible(row):
            self.EnsureVisible(row)

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

    def OnKeyDown(self, event):
        """Spacebar patches the selected instruction.

        This was a frame-wide accelerator, so it fired wherever the focus was - pressing
        Space after clicking a step button opened the patch dialog instead of stepping.
        """
        if event.ControlDown() and event.GetKeyCode() == ord("C"):
            self.OnCopy(event)
            return

        if event.GetKeyCode() != wx.WXK_SPACE:
            event.Skip()
            return

        row = self.GetNextItem(-1, wx.LIST_NEXT_ALL, wx.LIST_STATE_SELECTED)
        if row == -1:
            return

        self.OnPatchBytes(row)

    def OnContextMenu(self, event):
        pos = event.GetPosition()
        pos = self.ScreenToClient(pos)
        row, flags = self.HitTest(pos)
        if row == wx.NOT_FOUND:
            return

        menu = wx.Menu()
        miCopy = menu.Append(wx.ID_ANY, "Copy")
        miGoTo = menu.Append(wx.ID_ANY, "Go To")
        miGoToCIP = menu.Append(wx.ID_ANY, "Go To EIP/RIP")
        miSetCIP = menu.Append(wx.ID_ANY, "Set EIP/RIP")
        menu.AppendSeparator()
        miNopInstruction = menu.Append(wx.ID_ANY, "NOP Instruction")
        miPatchBytes = menu.Append(wx.ID_ANY, "Patch Bytes")
        miPatchHistory = menu.Append(wx.ID_ANY, "Patch History")
        menu.AppendSeparator()
        miDumpAddress = menu.Append(wx.ID_ANY, "Dump Address")
        miResolveAddress = menu.Append(wx.ID_ANY, "Resolve Export Name From Address")
        miResolveRef = menu.Append(wx.ID_ANY, "Resolve Export Name From Dereference")
        if self.resolveAllRefsStatus:
            miResolveAllRefs = menu.Append(wx.ID_ANY, "Resolve All Export Names for Calls")
            self.Bind(wx.EVT_MENU, self.OnResolveAllRefs, miResolveAllRefs)

        miStringAddress = menu.Append(wx.ID_ANY, "Resolve String From Address")
        miStringRef = menu.Append(wx.ID_ANY, "Resolve String From Dereference")
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
            self.Bind(wx.EVT_MENU, lambda e, s=slot: self.OnSetBreakpoint(row, s), id=bpId)

        menu.AppendSubMenu(bpMenu, "Set Breakpoint")
        miDataBp = menu.Append(wx.ID_ANY, "Set Data Breakpoint...")
        self.Bind(wx.EVT_MENU, lambda e, r=row: self.OnDataBreakpoint(r), miDataBp)

        self.Bind(wx.EVT_MENU, self.OnCopy, miCopy)
        self.Bind(wx.EVT_MENU, self.OnGoTo, miGoTo)
        self.Bind(wx.EVT_MENU, self.OnGoToCip, miGoToCIP)
        self.Bind(wx.EVT_MENU, lambda e: self.OnSetCip(row), miSetCIP)
        self.Bind(wx.EVT_MENU, lambda e: self.OnNopInstruction(row), miNopInstruction)
        self.Bind(wx.EVT_MENU, lambda e: self.OnPatchBytes(row), miPatchBytes)
        self.Bind(wx.EVT_MENU, self.OnPatchHistory, miPatchHistory)
        self.Bind(wx.EVT_MENU, lambda e, r=row: self.OnDumpAddress(r), miDumpAddress)
        self.Bind(wx.EVT_MENU, lambda e, r=row: self.OnResolveAddress(r), miResolveAddress)
        self.Bind(wx.EVT_MENU, lambda e, r=row: self.OnResolveRef(r), miResolveRef)
        self.Bind(wx.EVT_MENU, lambda e, r=row: self.OnStringAddress(r), miStringAddress)
        self.Bind(wx.EVT_MENU, lambda e, r=row: self.OnStringRef(r), miStringRef)
        self.Bind(wx.EVT_MENU, self.OnStepInto, miStepInto)
        self.Bind(wx.EVT_MENU, self.OnStepOver, miStepOver)
        self.Bind(wx.EVT_MENU, self.OnStepOut, miStepOut)
        self.Bind(wx.EVT_MENU, lambda e: self.OnRunUntil(row), miRunUntil)
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
        SetClipboard(text)

    def OnGoTo(self, event):
        addr = GetClipboardText().strip()
        dialog = wx.TextEntryDialog(self, "Enter hex address (e.g., 0x12345678) or Register:", "Go To Address", addr)
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
                else:
                    self.PushHistory(int(target, 16))
            except Exception:
                wx.MessageBox(f"Invalid register or hex address: {entry}", "Error", wx.OK | wx.ICON_ERROR)

        dialog.Destroy()

    def OnGoToCip(self, event):
        row = self.GetCipRow(self.parent.cip)
        self.HighlightCip(row)

    def OnSetCip(self, row):
        addrStr = self.GetItemText(row, 0).strip()
        try:
            addr = int(addrStr, 16)
            cip = "RIP"
            if self.parent.bits == 32:
                cip = "EIP"

            payload = f"{cip}|{addr:#X}"
            self.parent.SendCommand(CMD_SET_REGISTER, payload)
        except ValueError:
            wx.MessageBox(f"Invalid address for Set EIP/RIP: {addrStr}", "Error", wx.OK | wx.ICON_ERROR)

    def OnStepInto(self, event):
        self.parent.SendCommand(CMD_STEP_INTO)

    def OnStepOver(self, event):
        self.parent.SendCommand(CMD_STEP_OVER)

    def OnStepOut(self, event):
        self.parent.SendCommand(CMD_STEP_OUT)

    def OnRunUntil(self, row):
        addrStr = self.GetItemText(row, 0).strip()
        try:
            addr = int(addrStr, 16)
            payload = f"{addr:#X}"
            self.parent.SendCommand(CMD_RUN_UNTIL, payload)
        except ValueError:
            wx.MessageBox(f"Invalid address for Run Until: {addrStr}", "Error", wx.OK | wx.ICON_ERROR)

    def OnSetBreakpoint(self, row, slot):
        addrStr = self.GetItemText(row, 0).strip()
        try:
            addr = int(addrStr, 16)
            payload = f"{slot.lower()}|{addr:#X}"
            self.parent.SendCommand(CMD_SET_BREAKPOINT, payload)
        except ValueError:
            wx.MessageBox(f"Invalid address for Set Breakpoint: {addrStr}", "Error", wx.OK | wx.ICON_ERROR)

    def OnDataBreakpoint(self, row):
        """Prefill with the address the instruction references, else its own address."""
        addr = self.OperandAddressAt(row)
        if addr is None:
            addr = self.GetItemText(row, 0).strip()

        self.parent.PromptBreakpoint(addr)

    def ClearBpBackground(self, addr):
        self.bpAddrs.discard(addr)
        row = self.GetInstructionRow(addr)
        if row == wx.NOT_FOUND:
            return

        self.SetItemBackgroundColour(row, ACCENT_GREEN if row == self.cipRow else BG_INPUT)
        self.Refresh()

    def SetBpBackground(self, addr):
        self.bpAddrs.add(addr)
        row = self.GetInstructionRow(addr)
        if row == wx.NOT_FOUND:
            return

        if row != self.cipRow:
            self.SetItemBackgroundColour(row, COLOR_LIGHT_RED)
            self.Refresh()

    def GoToInstruction(self, addr):
        addr = int(addr, 16)
        row = self.GetInstructionRow(addr)
        if row == wx.NOT_FOUND:
            return row

        self.CenterRow(row)
        self.Select(row)
        self.Focus(row)
        self.Refresh()
        return row

    def GetColumnAtX(self, x):
        offset = 0
        for col in range(self.GetColumnCount()):
            width = self.GetColumnWidth(col)
            if offset <= x < offset + width:
                return col

            offset += width
        return -1

    @staticmethod
    def SafeEval(expr: str) -> int:
        ops = {
            ast.Add: operator.add,
            ast.Sub: operator.sub,
            ast.Mult: operator.mul,
            ast.Div: operator.floordiv,
            ast.FloorDiv: operator.floordiv,
            ast.USub: operator.neg,
        }

        def _eval(node):
            if isinstance(node, ast.Constant):
                return node.value
            elif isinstance(node, ast.Num):
                return node.n
            elif isinstance(node, ast.BinOp):
                return ops[type(node.op)](_eval(node.left), _eval(node.right))
            elif isinstance(node, ast.UnaryOp):
                return ops[type(node.op)](_eval(node.operand))
            else:
                raise ValueError("Unsupported expression")

        tree = ast.parse(expr, mode="eval")
        return _eval(tree.body)

    @staticmethod
    def ParseRegisters(regsText):
        registers = {}
        general = re.findall(r"\b([A-Z0-9]{2,3}):\s*([0-9A-Fa-f]{8,16})", regsText)
        for name, value in general:
            registers[name.upper()] = int(value, 16)

        xmm = re.findall(r"\bXMM(\d{1,2})\s*\.(Low|High)\s*:\s*([0-9A-Fa-f]{8,16})", regsText)
        for num, part, value in xmm:
            key = f"XMM{int(num):02}.{part}"
            registers[key.upper()] = int(value, 16)

        return registers

    def ParseOperandAddress(self, inst: str, ripBase: int) -> int | None:
        m = re.search(r"\[([A-Za-z]{2}:)?([^\]]+)\]", inst)
        if m:
            seg = m.group(1).lower()[:-1] if m.group(1) else None
            expr = m.group(2).replace(" ", "").lower()
            regsText = self.parent.regsDisplay.GetValue()
            regVals = {g.group(1).lower(): int(g.group(2), 16) for g in
                re.finditer(r"([A-Za-z0-9]+):\s*([0-9A-Fa-f]+)", regsText)}
            regVals["rip"] = ripBase
            for reg in sorted(regVals, key=len, reverse=True):
                expr = re.sub(rf"\b{reg}\b", str(regVals[reg]), expr)

            try:
                addr = self.SafeEval(expr)
            except Exception:
                return None

            if seg and seg in regVals:
                addr += regVals[seg]
            return addr

        # Accept any 0x literal that is plausibly an address, rather than counting digits.
        # The old bound was {8,16}, so a 32-bit target based at 0x400000 - where a direct call
        # disassembles as `CALL 0x401000`, six digits - resolved no operands at all.
        # IsValidHexAddress is the project's own notion of plausible, and still rejects the
        # small immediates the digit count was there to exclude.
        for match in re.finditer(r"\b0x[0-9A-Fa-f]+\b", inst):
            if IsValidHexAddress(match.group(0)):
                return int(match.group(0), 16)

        return None

    def OnOperandHover(self, event):
        x, y = event.GetPosition()
        row, flags = self.HitTest(wx.Point(x, y))
        if row == wx.NOT_FOUND or row == self.lastTipRow:
            if row == wx.NOT_FOUND:
                self.SetToolTip(None)
                self.lastTipRow = None

            return event.Skip()

        col = self.GetColumnAtX(x)
        if col != 2:
            return event.Skip()

        inst = self.GetItemText(row, 2)
        instLen = len(self.GetItemText(row, 1)) // 2
        ripBase = int(self.GetItemText(row, 0), 16) + instLen
        addr = self.ParseOperandAddress(inst, ripBase)
        if addr is None:
            self.SetToolTip(None)
            self.lastTipRow = None
            return event.Skip()

        # Tooltip only: hover used to overwrite the clipboard on every row change.
        self.SetToolTip(f"{addr:#x}")
        self.lastTipRow = row
        return event.Skip()

    def PushHistory(self, addr: int):
        self.backHistory.append(addr)

    def OnBack(self, event):
        """Handle ESC: go back to previous address in history or home CIP."""
        if self.backHistory:
            addr = self.backHistory.pop()
        else:
            addr = self.parent.cip

        if addr is None:
            return

        row = self.GetInstructionRow(addr)
        if row != -1:
            self.HighlightCip(row)
            return

        # History addresses are pinned against eviction, so this only happens when the region
        # itself was flushed (module unload, fault, page map change). Re-fetching here would
        # mean calling JumpTo, which sets self.cip and would highlight this address as the
        # current instruction when it is not.
        wx.MessageBox(f"Address {addr:#x} is no longer mapped.", "Info", wx.OK | wx.ICON_INFORMATION)

    def OperandAddressAt(self, row: int) -> int | None:
        """The address the instruction on `row` references, or None if it references none.

        These actions used to take their operand from the clipboard, which hover happened to
        fill in. That made the clipboard a load-bearing data channel: copying anything else
        between hovering and right-clicking silently redirected the action, and OnResolveRef
        additionally used the last *hovered* row rather than the one you clicked.
        """
        if row < 0 or row >= self.GetItemCount():
            return None

        try:
            instLen = len(self.GetItemText(row, 1)) // 2
            ripBase = int(self.GetItemText(row, 0), 16) + instLen
        except ValueError:
            return None

        return self.ParseOperandAddress(self.GetItemText(row, 2), ripBase)

    def OnDumpAddress(self, row):
        addr = self.OperandAddressAt(row)
        if addr is None:
            self.parent.AppendConsole("No address operand on this instruction.")
            return

        self.parent.SendCommand(CMD_MEM_DUMP, f"{addr:#x}", tag=self.parent.NextTag(TAG_DUMP))

    def OnResolveAddress(self, row):
        addr = self.OperandAddressAt(row)
        if addr is None:
            self.parent.AppendConsole("No address operand on this instruction.")
            return

        export = self.parent.exports.get(addr)
        self.parent.AppendConsole(export or f"No export known at {addr:#x}")

    def OnResolveRef(self, row):
        target = self.OperandAddressAt(row)
        if target is None:
            self.parent.AppendConsole("No address operand on this instruction.")
            return

        try:
            instAddr = int(self.GetItemText(row, 0), 16)
        except ValueError:
            return

        if instAddr not in self.parent.resolvedExports:
            self.parent.resolvedExports[instAddr] = {target: ""}
            self.parent.ResolveRef(target)

    def OnResolveAllRefs(self, event):
        self.resolveAllRefsStatus = False
        self.parent.DeReferenceCalls()

    def OnStringAddress(self, row):
        addr = self.OperandAddressAt(row)
        if addr is None:
            self.parent.AppendConsole("No address operand on this instruction.")
            return

        string = self.parent.resolvedStrings.get(addr)
        self.parent.AppendConsole(string or f"No string resolved at {addr:#x}")

    def OnStringRef(self, row):
        addr = self.OperandAddressAt(row)
        if addr is None:
            self.parent.AppendConsole("No address operand on this instruction.")
            return

        if addr not in self.parent.resolvedStrings:
            self.parent.ResolveString(addr)

    def OnNopInstruction(self, row):
        addrStr = self.GetItemText(row, 0)
        if addrStr and IsValidHexAddress(addrStr):
            self.parent.SendCommand(CMD_NOP_INSTRUCTION, addrStr)

    def GetOriginalBytes(self, row: int, numBytes: int) -> str:
        hexStr = ""
        collectedBytes = 0
        currentRow = row
        totalRows = self.GetItemCount()
        while collectedBytes < numBytes and currentRow < totalRows:
            rowHex = self.GetItemText(currentRow, 1)
            hexStr += rowHex
            collectedBytes = len(hexStr) // 2
            currentRow += 1

        return hexStr[: numBytes * 2]

    def AssemblePatch(self, asmText: str, baseAddress: str) -> tuple[str, list[PatchEntry]]:
        addr = int(baseAddress, 16)
        return self.parent.assembler.AssembleAt(asmText, addr)

    def UpdatePatchHistory(self, newEntries: list[PatchEntry], row: int):
        for entry in newEntries:
            numBytes = len(entry.patchedBytes) // 2
            orig = self.GetOriginalBytes(row, numBytes)
            entry.originalBytes = orig
            self.parent.patchHistory.append(entry)
            self.parent.patchHistoryByAddr[entry.address].append(entry)

    def OnPatchBytes(self, row):
        addrStr = self.GetItemText(row, 0)
        instrStr = self.GetItemText(row, 2)
        if addrStr and IsValidHexAddress(addrStr):
            dlg = PatchDialog(self, instrStr)
            if dlg.ShowModal() == wx.ID_OK:
                asmText = dlg.GetAsmText()
                dlg.Destroy()
                codeHex, newEntries = self.AssemblePatch(asmText, addrStr)
                if codeHex and not "error" in codeHex:
                    previewTxt = f"{codeHex}    {asmText}"
                    confirmDlg = ConfirmPatchDialog(self, previewTxt)
                    if confirmDlg.ShowModal() == wx.ID_OK:
                        confirmDlg.Destroy()
                        data = f"{int(addrStr, 16):#x}|{codeHex}"
                        self.UpdatePatchHistory(newEntries, row)
                        self.parent.SendCommand(CMD_PATCH_BYTES, data)
                else:
                    wx.MessageBox(f"Instructions were not assembled: {codeHex}", "Info", wx.OK | wx.ICON_INFORMATION)
            else:
                dlg.Destroy()

    def OnPatchHistory(self, event):
        dlg = PatchHistoryDialog(self, self.parent.patchHistory)
        dlg.ShowModal()
        dlg.Destroy()


class RegsTextCtrl(wx.TextCtrl):
    def __init__(self, parent, style, console=None):
        """TextCtrl subclass"""
        super().__init__(parent, style=style)
        # `console` separates the wx parent from the ConsolePanel these controls call
        # back into: with the splitter layout the wx parent is a splitter pane.
        self.parent = console or parent
        self.Bind(wx.EVT_CONTEXT_MENU, self.OnContextMenu)

    def OnContextMenu(self, event):
        menu = wx.Menu()
        miCopy = menu.Append(wx.ID_ANY, "Copy")
        miDumpAddress = menu.Append(wx.ID_ANY, "Dump Memory Address")
        miDataBp = menu.Append(wx.ID_ANY, "Set Data Breakpoint...")
        miFollowAddress = menu.Append(wx.ID_ANY, "Follow Address")
        miExportAddress = menu.Append(wx.ID_ANY, "Resolve Export Name From Address")
        miExportDeref = menu.Append(wx.ID_ANY, "Resolve Export Name From Dereference")
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
        self.Bind(wx.EVT_MENU, lambda e: self.parent.PromptBreakpoint(self.GetStringSelection().strip()), miDataBp)
        self.Bind(wx.EVT_MENU, self.OnFollowAddress, miFollowAddress)
        self.Bind(wx.EVT_MENU, self.OnResolveAddress, miExportAddress)
        self.Bind(wx.EVT_MENU, self.OnResolveRef, miExportDeref)
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

        menu.AppendSeparator()
        regMenu = wx.Menu()
        regs = ["RAX", "RBX", "RCX", "RDX", "RSI", "RDI", "RSP", "RBP", "R8", "R9", "R10", "R11", "R12", "R13", "R14", "R15"]
        if self.parent.bits == 32:
            regs = ["EAX", "EBX", "ECX", "EDX", "ESI", "EDI", "ESP", "EBP"]

        for reg in regs:
            miName = f"miSet{reg}"
            mi = regMenu.Append(wx.ID_ANY, f"Set {reg}")
            setattr(self, miName, mi)
            self.Bind(wx.EVT_MENU, lambda e, r=reg: self.OnSetRegister(r), mi)

        menu.AppendSubMenu(regMenu, "Set Register")

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
        if addrStr and IsValidHexAddress(addrStr):
            row = self.parent.disassemblyConsole.GoToInstruction(addrStr)
            if row == wx.NOT_FOUND:
                self.parent.AppendConsole("Address not found")

    def OnCopy(self, event):
        text = self.GetStringSelection().strip()
        SetClipboard(text)

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
        self.parent.SendCommand(CMD_MOD_FLAG, cmd)

    def OnSetRegister(self, reg):
        prompt = f"Enter new value for {reg} (decimal or 0x-prefixed hex):"
        valueStr = wx.GetTextFromUser(prompt, "Set Register", "", self)
        if not valueStr:
            return

        try:
            val = int(valueStr, 0)
        except ValueError:
            wx.MessageBox(f"'{valueStr}' is not a valid number.", "Error", wx.ICON_ERROR)
            return

        payload = f"{reg}|{val:#X}"
        self.parent.SendCommand(CMD_SET_REGISTER, payload)

    def OnResolveAddress(self, event):
        addrStr = self.GetStringSelection().strip()
        try:
            addrInt = int(addrStr, 16)
        except ValueError:
            return

        export = self.parent.exports.get(addrInt)
        self.parent.AppendConsole(export)
        return

    def OnResolveRef(self, event):
        addrStr = self.GetStringSelection().strip()
        self.parent.ResolveRef(addrStr)


class StackListCtrl(wx.ListCtrl):
    def __init__(self, parent, console=None):
        super().__init__(parent, style=wx.LC_REPORT)
        # `console` separates the wx parent from the ConsolePanel these controls call
        # back into: with the splitter layout the wx parent is a splitter pane.
        self.parent = console or parent
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
        miExportAddress = menu.Append(wx.ID_ANY, "Export Name From Address")
        miExportValue = menu.Append(wx.ID_ANY, "Export Name From Value")
        miExportValueRef = menu.Append(wx.ID_ANY, "Export Name From Value Dereference")

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
        self.Bind(wx.EVT_MENU, lambda e: self.OnResolveAddress(row), miExportAddress)
        self.Bind(wx.EVT_MENU, lambda e: self.OnResolveValue(row), miExportValue)
        self.Bind(wx.EVT_MENU, lambda e: self.OnResolveValueRef(row), miExportValueRef)

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
        SetClipboard(text)

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

    def OnResolveAddress(self, row):
        addrStr = self.data[row][0]
        try:
            addrInt = int(addrStr, 16)
        except ValueError:
            return

        export = self.parent.exports.get(addrInt)
        self.parent.AppendConsole(export)
        return

    def OnResolveValue(self, row):
        addrStr = self.data[row][1]
        try:
            addrInt = int(addrStr, 16)
        except ValueError:
            return

        export = self.parent.exports.get(addrInt)
        self.parent.AppendConsole(export)
        return

    def OnResolveValueRef(self, row):
        addrStr = self.data[row][1]
        self.parent.ResolveRef(addrStr)


class MemDumpListCtrl(wx.ListCtrl):
    def __init__(self, parent, console=None):
        super().__init__(parent, style=wx.LC_REPORT)
        # `console` separates the wx parent from the ConsolePanel these controls call
        # back into: with the splitter layout the wx parent is a splitter pane.
        self.parent = console or parent
        self.InsertColumn(0, "Address", width=170)
        self.InsertColumn(1, "Hex Dump", width=400)
        self.InsertColumn(2, "Ascii", width=150)
        self.data = []
        self.addr = None
        self.backHistory: list[int] = []
        self.Bind(wx.EVT_CONTEXT_MENU, self.OnContextMenu)

    def UpdateData(self, data):
        """Populate the list control from a string of lines."""
        if self.GetItemCount() > 0:
            target = self.GetItemText(0, 0)
            self.PushHistory(int(target, 16))

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
        row, _ = self.HitTest(pos)
        menu = wx.Menu()
        miCopy = menu.Append(wx.ID_ANY, "Copy")
        miSaveToFile = menu.Append(wx.ID_ANY, "Save Memory To File...")
        self.Bind(wx.EVT_MENU, self.OnCopy, miCopy)
        self.Bind(wx.EVT_MENU, self.OnSaveMemoryToFile, miSaveToFile)
        if row != wx.NOT_FOUND and row < len(self.data):
            menu.AppendSeparator()
            miDataBp = menu.Append(wx.ID_ANY, "Set Data Breakpoint...")
            self.Bind(wx.EVT_MENU, lambda e, r=row: self.parent.PromptBreakpoint(self.data[r][0]), miDataBp)
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
        SetClipboard(text)

    def OnDumpAddress(self, event):
        if isinstance(self.addr, int):
            self.addr = f"{self.addr:x}"
        self.parent.memAddressInput.SetValue(self.addr)
        evt = wx.CommandEvent(wx.EVT_TEXT_ENTER.typeId, self.parent.memAddressInput.GetId())
        self.parent.OnAddressEnter(evt)

    def PushHistory(self, addr: int):
        self.backHistory.append(addr)

    def OnBack(self, event):
        """Handle ESC: go back to previous address"""
        if not self.backHistory:
            return
        self.addr = self.backHistory[-1]
        if len(self.backHistory) > 1:
            self.addr = self.backHistory.pop()

        self.OnDumpAddress(event)

    def DumpFormatDialog(self):
        dlg = wx.SingleChoiceDialog(
            None,
            "Select the format to save:",
            "Save Format",
            ["Full View (Address + Hex + ASCII)", "Hex Dump Only", "ASCII Only", "Raw Bytes", "C Style", "Intel Hex"],
        )
        if dlg.ShowModal() == wx.ID_OK:
            return dlg.GetStringSelection()

        return None

    def OnSaveMemoryToFile(self, event):
        selection = self.DumpFormatDialog()
        if not selection:
            return

        dlg = wx.FileDialog(self, "Save Memory Dump", wildcard="All files (*.*)|*.*", style=wx.FD_SAVE | wx.FD_OVERWRITE_PROMPT)
        if dlg.ShowModal() != wx.ID_OK:
            return

        path = dlg.GetPath()

        format_to_ext = {
            "Full View (Address + Hex + ASCII)": ".txt",
            "Hex Dump Only": ".txt",
            "ASCII Only": ".txt",
            "Raw Bytes": ".bin",
            "C Style": ".c",
            "Intel Hex": ".hex",
        }
        default_ext = format_to_ext.get(selection, ".txt")
        if not Path(path).suffix:
            path += default_ext

        ext = Path(path).suffix.lower()
        is_binary = ext == ".bin"

        try:
            with open(path, "wb" if is_binary else "w", encoding=None if is_binary else "utf-8") as f:
                if selection == "Full View (Address + Hex + ASCII)":
                    for row in range(self.GetItemCount()):
                        addr = self.GetItemText(row, 0)
                        hexpart = self.GetItemText(row, 1)
                        asciipart = self.GetItemText(row, 2)
                        f.write(f"{addr}  {hexpart:<48}  {asciipart}\n")

                elif selection == "Hex Dump Only":
                    for row in range(self.GetItemCount()):
                        hexpart = self.GetItemText(row, 1)
                        f.write(f"{hexpart}\n")

                elif selection == "ASCII Only":
                    for row in range(self.GetItemCount()):
                        asciipart = self.GetItemText(row, 2)
                        f.write(f"{asciipart}\n")

                elif selection == "Raw Bytes":
                    for row in range(self.GetItemCount()):
                        hexpart = self.GetItemText(row, 1).strip()
                        hexbytes = bytes.fromhex(hexpart)
                        f.write(hexbytes)

                elif selection == "C Style":
                    all_bytes = bytearray()
                    for row in range(self.GetItemCount()):
                        hexpart = self.GetItemText(row, 1).strip()
                        all_bytes.extend(bytes.fromhex(hexpart))

                    f.write("unsigned char dump[] = {\n")
                    for i in range(0, len(all_bytes), 12):
                        line = ", ".join(f"0x{b:02X}" for b in all_bytes[i : i + 12])
                        f.write(f"    {line},\n")

                    f.write("};\n")

                elif selection == "Intel Hex":
                    all_bytes = bytearray()
                    for row in range(self.GetItemCount()):
                        hexpart = self.GetItemText(row, 1).strip()
                        all_bytes.extend(bytes.fromhex(hexpart))

                    addr = 0
                    for i in range(0, len(all_bytes), 16):
                        chunk = all_bytes[i : i + 16]
                        record = bytearray()
                        record.append(len(chunk))
                        record.append((addr >> 8) & 0xFF)
                        record.append(addr & 0xFF)
                        record.append(0x00)
                        record.extend(chunk)
                        checksum = (-sum(record)) & 0xFF
                        hexline = ":" + "".join(f"{b:02X}" for b in record) + f"{checksum:02X}\n"
                        f.write(hexline)
                        addr += len(chunk)

                    f.write(":00000001FF\n")

                else:
                    wx.MessageBox("Unknown format selected.", "Error", wx.ICON_ERROR)

        except Exception as e:
            wx.MessageBox(f"Failed to save file:\n{e}", "Error", wx.ICON_ERROR)


class ThreadListCtrl(wx.ListCtrl):
    """List control to display threads with columns: TID, Start Address."""

    def __init__(self, parent):
        super().__init__(parent, style=wx.LC_REPORT | wx.LC_SINGLE_SEL)
        self.parent = parent
        self.data: list[tuple[str, str]] = []
        self.InsertColumn(0, "TID", width=60)
        self.InsertColumn(1, "Start Address", width=160)
        self.Bind(wx.EVT_CONTEXT_MENU, self.OnContextMenu)
        self.Bind(wx.EVT_MOTION, self.OnMouseOver)
        self.Bind(wx.EVT_LIST_ITEM_ACTIVATED, self.OnActivated)

    def UpdateData(self, threadEntries: list[tuple[str, str]]):
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

    def OnContextMenu(self, event):
        pos = event.GetPosition()
        pos = self.ScreenToClient(pos)
        row, flags = self.HitTest(pos)
        if row == wx.NOT_FOUND:
            return

        menu = wx.Menu()
        miFollowStartAddress = menu.Append(wx.ID_ANY, "Follow Start Address")
        self.Bind(wx.EVT_MENU, lambda e: self.OnFollowStartAddress(row), miFollowStartAddress)
        miInspect = menu.Append(wx.ID_ANY, "Inspect Thread" if row else "Return To Halted Thread")
        self.Bind(wx.EVT_MENU, lambda e, r=row: self.OnInspectThread(r), miInspect)
        self.PopupMenu(menu, pos)
        menu.Destroy()

    def OnActivated(self, event):
        self.OnInspectThread(event.GetIndex())

    def OnInspectThread(self, row):
        """Row 0 is the halted thread - HandleThreads always sorts it first."""
        if row == 0:
            self.parent.ReturnToHaltedThread()
            return

        tid = self.GetItemText(row, 0).strip()
        if tid:
            self.parent.InspectThread(tid)

    def OnFollowStartAddress(self, row):
        addrStr = self.GetItemText(row, 1).strip()
        row = self.parent.disassemblyConsole.GoToInstruction(addrStr)
        if row == wx.NOT_FOUND:
            self.parent.AppendConsole("Address not found")

    def OnMouseOver(self, event):
        x, y = event.GetPosition()
        row, flags = self.HitTest(wx.Point(x, y))
        if row == wx.NOT_FOUND:
            if row == wx.NOT_FOUND:
                self.SetToolTip(None)
            return event.Skip()

        tid = self.GetItemText(row, 0)
        if not tid:
            self.SetToolTip(None)
            return event.Skip()

        tidStr = f"{int(tid):#x}"
        self.SetToolTip(tidStr)
        return event.Skip()


class BreakpointsListCtrl(wx.ListCtrl):
    """List control to display breakpoints with columns: dr, Address."""

    def __init__(self, parent):
        super().__init__(parent, style=wx.LC_REPORT | wx.LC_SINGLE_SEL)
        self.parent = parent
        self.InsertColumn(0, "DR", width=40)
        self.InsertColumn(1, "Address", width=160)
        self.InsertColumn(2, "Type", width=50)
        self.InsertColumn(3, "Size", width=45)
        self.Bind(wx.EVT_CONTEXT_MENU, self.OnContextMenu)

    def UpdateData(self, bps: list[tuple[str, str, str, str]]):
        """Populate the list with (dr, address, type, size)."""
        self.DeleteAllItems()
        for i, (dr, addr, bpType, size) in enumerate(bps):
            row = self.InsertItem(i, dr)
            self.SetItem(row, 1, addr)
            self.SetItem(row, 2, BP_TYPE_LABELS.get(bpType, bpType))
            self.SetItem(row, 3, size)

    def OnContextMenu(self, event):
        pos = event.GetPosition()
        pos = self.ScreenToClient(pos)
        row, flags = self.HitTest(pos)

        menu = wx.Menu()
        # Available on empty space too, so a breakpoint can be added with nothing selected.
        miAddBreakpoint = menu.Append(wx.ID_ANY, "Add Breakpoint...")
        self.Bind(wx.EVT_MENU, lambda e: self.parent.PromptBreakpoint(), miAddBreakpoint)
        if row != wx.NOT_FOUND:
            menu.AppendSeparator()
            miDeleteBreakpoint = menu.Append(wx.ID_ANY, "Delete Breakpoint")
            miFollowBreakpoint = menu.Append(wx.ID_ANY, "Follow Address")
            self.Bind(wx.EVT_MENU, lambda e: self.OnDeleteBreakpoint(row), miDeleteBreakpoint)
            self.Bind(wx.EVT_MENU, lambda e: self.OnFollowBreakpoint(row), miFollowBreakpoint)
        self.PopupMenu(menu, pos)
        menu.Destroy()

    def OnDeleteBreakpoint(self, row):
        index = self.GetItemText(row, 0).strip()
        self.parent.SendCommand(CMD_DELETE_BREAKPOINT, index)

    def OnFollowBreakpoint(self, row):
        addrStr = self.GetItemText(row, 1).strip()
        row = self.parent.disassemblyConsole.GoToInstruction(addrStr)
        if row == wx.NOT_FOUND:
            self.parent.AppendConsole("Address not found")


class ModulesListCtrl(wx.ListCtrl):
    """List control to display modules with columns: Address, Name."""

    def __init__(self, parent):
        super().__init__(parent, style=wx.LC_REPORT | wx.LC_SINGLE_SEL)
        self.parent = parent
        self.dlg = None
        self.lastHoverRow = None
        self.InsertColumn(0, "Address", width=160)
        self.InsertColumn(1, "Size", width=80)
        self.InsertColumn(2, "Name", width=160)
        self.InsertColumn(3, "Path", width=160)
        self.Bind(wx.EVT_CONTEXT_MENU, self.OnContextMenu)

    def UpdateData(self, modules: list[tuple[str, str, str, str]]):
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
        mi = menu.Append(wx.ID_ANY, "Exports")
        self.Bind(wx.EVT_MENU, lambda e: self.OnShowExports(row), mi)
        self.PopupMenu(menu, pos)
        menu.Destroy()

    def OnShowExports(self, row):
        modName = self.GetItemText(row, 2)
        matches = []
        for addr, full in self.parent.exports.items():
            if full.startswith(modName + "!"):
                _, sym = full.split("!", 1)
                matches.append((sym, addr))

        if not matches:
            wx.MessageBox(f"No exports for module {modName}", "Info", wx.OK | wx.ICON_INFORMATION)
            return

        self.dlg = ExportsDialog(self, modName, matches)
        self.dlg.ShowModal()
        self.dlg.Destroy()
        self.dlg = None


class ExportsDialog(wx.Dialog):
    def __init__(self, parent, mod_name, exports):
        super().__init__(
            parent, title=f"Exports for {mod_name}", size=wx.Size(500, 600), style=wx.DEFAULT_DIALOG_STYLE | wx.RESIZE_BORDER
        )
        self.parent = parent
        self.exports = exports
        self.listCtrl = wx.ListCtrl(self, style=wx.LC_REPORT | wx.BORDER_SUNKEN | wx.LC_SINGLE_SEL)
        self.listCtrl.InsertColumn(0, "Address", width=120)
        self.listCtrl.InsertColumn(1, "Name", width=350)
        self.exports.sort(key=lambda x: x[1])
        for i, (symName, addr) in enumerate(self.exports):
            row = self.listCtrl.InsertItem(i, f"{int(addr):#x}")
            self.listCtrl.SetItem(row, 1, symName)

        self.listCtrl.Bind(wx.EVT_KEY_DOWN, self.OnKeyDown)
        self.listCtrl.Bind(wx.EVT_CONTEXT_MENU, self.OnContextMenu)

        self.ID_SEARCH = wx.NewIdRef()
        accels = wx.AcceleratorTable(
            [
                (wx.ACCEL_CTRL, ord("F"), self.ID_SEARCH),
            ]
        )

        self.SetAcceleratorTable(accels)
        self.Bind(wx.EVT_MENU, self.OnSearch, id=self.ID_SEARCH)

        sizer = wx.BoxSizer(wx.VERTICAL)
        sizer.Add(self.listCtrl, 1, wx.EXPAND | wx.ALL, 10)
        btn = wx.Button(self, wx.ID_OK, "Close")
        sizer.Add(btn, 0, wx.ALIGN_CENTER | wx.ALL, 10)
        self.SetSizer(sizer)
        self.Layout()

    def OnKeyDown(self, event):
        if event.ControlDown() and event.GetKeyCode() == ord("C"):
            self.OnCopyItem(event)
        else:
            event.Skip()

    def OnContextMenu(self, event):
        menu = wx.Menu()
        copyItem = menu.Append(wx.ID_COPY, "Copy")
        self.Bind(wx.EVT_MENU, self.OnCopyItem, copyItem)
        self.PopupMenu(menu)
        menu.Destroy()

    def OnCopyItem(self, event):
        index = self.listCtrl.GetFirstSelected()
        if index == -1:
            return

        address = self.listCtrl.GetItemText(index)
        name = self.listCtrl.GetItem(index, 1).GetText()
        text = f"{address}\t{name}"
        if wx.TheClipboard.Open():
            wx.TheClipboard.SetData(wx.TextDataObject(text))
            wx.TheClipboard.Close()

    def OnSearch(self, event):
        dlg = SearchDialog(self)
        dlg.ShowModal()
        dlg.Destroy()


class BreakpointDialog(wx.Dialog):
    """Address, type, size and slot for a hardware breakpoint.

    Data watches are what debug registers are actually good at - break when a buffer is
    written rather than when code runs - but the debugger only ever set BP_EXEC before.
    """

    def __init__(self, parent, address: str = ""):
        super().__init__(parent, title="Set Breakpoint")
        self.types = [BP_EXEC, BP_WRITE, BP_READWRITE]

        grid = wx.FlexGridSizer(rows=0, cols=2, hgap=8, vgap=8)
        grid.AddGrowableCol(1, 1)

        grid.Add(wx.StaticText(self, label="Address:"), flag=wx.ALIGN_CENTER_VERTICAL)
        self.addressCtrl = wx.TextCtrl(self, value=address)
        grid.Add(self.addressCtrl, flag=wx.EXPAND)

        grid.Add(wx.StaticText(self, label="Type:"), flag=wx.ALIGN_CENTER_VERTICAL)
        self.typeCtrl = wx.Choice(self, choices=[BP_TYPE_LABELS[t] for t in self.types])
        self.typeCtrl.SetSelection(0)
        self.typeCtrl.Bind(wx.EVT_CHOICE, self.OnTypeChanged)
        grid.Add(self.typeCtrl, flag=wx.EXPAND)

        grid.Add(wx.StaticText(self, label="Size:"), flag=wx.ALIGN_CENTER_VERTICAL)
        self.sizeCtrl = wx.Choice(self, choices=[str(s) for s in BP_SIZES])
        self.sizeCtrl.SetSelection(0)
        grid.Add(self.sizeCtrl, flag=wx.EXPAND)

        grid.Add(wx.StaticText(self, label="Slot:"), flag=wx.ALIGN_CENTER_VERTICAL)
        self.slotCtrl = wx.Choice(self, choices=["next", "0", "1", "2", "3"])
        self.slotCtrl.SetSelection(0)
        grid.Add(self.slotCtrl, flag=wx.EXPAND)

        outer = wx.BoxSizer(wx.VERTICAL)
        outer.Add(grid, 1, wx.EXPAND | wx.ALL, 10)
        buttons = self.CreateStdDialogButtonSizer(wx.OK | wx.CANCEL)
        outer.Add(buttons, 0, wx.EXPAND | wx.LEFT | wx.RIGHT | wx.BOTTOM, 10)
        self.SetSizerAndFit(outer)

        self.OnTypeChanged(None)
        self.Bind(wx.EVT_BUTTON, self.OnOk, id=wx.ID_OK)

    def OnTypeChanged(self, event):
        # An execute breakpoint must keep LEN at one byte, so size is not a choice there.
        self.sizeCtrl.Enable(self.SelectedType() != BP_EXEC)

    def SelectedType(self) -> str:
        return self.types[self.typeCtrl.GetSelection()]

    def OnOk(self, event):
        values = self.GetValues()
        if values is None:
            return

        self.EndModal(wx.ID_OK)

    def GetValues(self):
        """Return (slot, type, size, address) or None, reporting why if it is invalid."""
        text = self.addressCtrl.GetValue().strip()
        if not IsValidHexAddress(text):
            wx.MessageBox(f"'{text}' is not a valid address.", "Set Breakpoint", wx.OK | wx.ICON_ERROR)
            return None

        address = int(text, 16)
        bpType = self.SelectedType()
        size = BP_SIZES[self.sizeCtrl.GetSelection()] if bpType != BP_EXEC else 1
        # x86 requires a data breakpoint's address to be aligned to its length; a misaligned
        # one silently watches the wrong bytes rather than failing.
        if bpType != BP_EXEC and address % size:
            wx.MessageBox(
                f"A {size}-byte watch needs a {size}-byte aligned address.\n"
                f"{address:#x} is not aligned; try {address - (address % size):#x}.",
                "Set Breakpoint",
                wx.OK | wx.ICON_ERROR,
            )
            return None

        return self.slotCtrl.GetStringSelection(), bpType, size, address


class CallStackListCtrl(wx.ListCtrl):
    """Walked call frames: where each one returns to, and the call that made it.

    The Stack pane beside this one shows raw stack words, which is what you want for
    arguments and locals; this answers the different question of how execution got here.
    """

    def __init__(self, parent, console=None):
        super().__init__(parent, style=wx.LC_REPORT | wx.LC_SINGLE_SEL)
        self.parent = console or parent
        self.data: list[tuple[str, str, str, str]] = []
        self.InsertColumn(0, "#", width=35)
        self.InsertColumn(1, "Return To", width=150)
        self.InsertColumn(2, "Symbol", width=200)
        self.InsertColumn(3, "Frame", width=150)
        self.InsertColumn(4, "Call Site", width=220)
        self.Bind(wx.EVT_CONTEXT_MENU, self.OnContextMenu)
        self.Bind(wx.EVT_LIST_ITEM_ACTIVATED, self.OnActivated)

    def UpdateData(self, frames: list[tuple[str, str, str, str]]):
        """Populate from (index, returnAddress, framePointer, callSite)."""
        self.DeleteAllItems()
        self.data = frames
        for i, (index, returnAddr, framePtr, callSite) in enumerate(frames):
            row = self.InsertItem(i, index)
            self.SetItem(row, 1, returnAddr)
            self.SetItem(row, 2, self.ResolveSymbol(returnAddr))
            self.SetItem(row, 3, framePtr)
            self.SetItem(row, 4, callSite)

    def ResolveSymbol(self, addrStr: str) -> str:
        """Nearest known export, falling back to the containing module's name."""
        try:
            addr = int(addrStr, 16)
        except ValueError:
            return ""

        return self.parent.NearestExport(addr) or self.parent.ModuleNameFor(addr)

    def OnActivated(self, event):
        self.FollowFrame(event.GetIndex())

    def OnContextMenu(self, event):
        pos = self.ScreenToClient(event.GetPosition())
        row, _ = self.HitTest(pos)
        if row == wx.NOT_FOUND:
            return

        menu = wx.Menu()
        miFollow = menu.Append(wx.ID_ANY, "Follow Return Address")
        miCopy = menu.Append(wx.ID_ANY, "Copy")
        self.Bind(wx.EVT_MENU, lambda e, r=row: self.FollowFrame(r), miFollow)
        self.Bind(wx.EVT_MENU, lambda e, r=row: SetClipboard("\t".join(self.data[r])), miCopy)
        self.PopupMenu(menu, pos)
        menu.Destroy()

    def FollowFrame(self, row: int):
        if row < 0 or row >= len(self.data):
            return

        addrStr = self.data[row][1]
        if self.parent.disassemblyConsole.GoToInstruction(addrStr) == wx.NOT_FOUND:
            self.parent.AppendConsole(f"Frame address {addrStr} is not in the decoded window.")
