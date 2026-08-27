import json
import os

import wx
import wx.grid as gridlib

from CAPEsolo.capelib.js_log import GetJsLogPath, JsLog
from CAPEsolo.capelib.path_utils import path_exists

from .custom_grid import CopyableGrid
from .key_event import KeyEventHandlerMixin
from .theme import FONT_CODE, GRID_ROW_ALT, apply_theme

ALL_EVENTS = "<All events>"


class JsConsolePanel(wx.Panel, KeyEventHandlerMixin):
    def __init__(self, parent):
        super().__init__(parent)
        self.analysisDir = parent.analysisDir
        self.results = parent.results
        self.BindKeyEvents()
        self.jsLogComplete = False
        self.myevents = []
        self.pageEvents = []
        self.category = ALL_EVENTS
        self.numevents = 0
        self.current_page = 1
        self.items_per_page = 100
        self.InitUI()

    def InitUI(self):
        vbox = wx.BoxSizer(wx.VERTICAL)

        vbox.AddSpacer(10)
        self.jsLogButton = wx.Button(self, label="Process JS Log")
        self.jsLogButton.Bind(wx.EVT_BUTTON, self.ProcessJsLog)
        self.jsLogButton.Disable()
        vbox.Add(self.jsLogButton, proportion=0, flag=wx.ALL, border=5)

        self.categoryDropdown = wx.ComboBox(self, style=wx.CB_READONLY)
        self.categoryDropdown.Bind(wx.EVT_COMBOBOX, self.OnCatView)
        vbox.Add(wx.StaticText(self, label="Events:"), flag=wx.LEFT | wx.TOP, border=5)
        vbox.Add(
            self.categoryDropdown,
            proportion=0,
            flag=wx.EXPAND | wx.LEFT | wx.RIGHT | wx.BOTTOM,
            border=5,
        )

        self.grid = CopyableGrid(self, 0, 3)
        for col, label in enumerate(("Time", "Event", "Summary")):
            self.grid.SetColLabelValue(col, label)
        self.grid.SetColLabelAlignment(wx.ALIGN_CENTRE, wx.ALIGN_CENTRE)
        summaryAttr = gridlib.GridCellAttr()
        summaryAttr.SetAlignment(wx.ALIGN_LEFT, wx.ALIGN_CENTRE)
        self.grid.SetColAttr(2, summaryAttr)
        self.grid.SetRowLabelSize(0)
        self.grid.EnableEditing(False)
        self.grid.Bind(gridlib.EVT_GRID_SELECT_CELL, self.OnSelectCell)
        self.grid.Hide()
        vbox.Add(
            self.grid,
            proportion=2,
            flag=wx.EXPAND | wx.LEFT | wx.RIGHT | wx.BOTTOM,
            border=5,
        )

        self.pagination_sizer = wx.BoxSizer(wx.HORIZONTAL)

        self.first_page_button = wx.Button(self, label="<<")
        self.first_page_button.Bind(wx.EVT_BUTTON, self.OnFirstPage)
        self.first_page_button.Disable()
        self.pagination_sizer.Add(self.first_page_button, 0, wx.ALL, 5)

        self.prev_button = wx.Button(self, label="Previous")
        self.prev_button.Bind(wx.EVT_BUTTON, self.OnPrevPage)
        self.prev_button.Disable()
        self.pagination_sizer.Add(self.prev_button, 0, wx.ALL, 5)

        self.page_label = wx.StaticText(self, label="Page 1 of 1")
        self.pagination_sizer.Add(self.page_label, 0, wx.ALL | wx.CENTER, 5)

        self.page_input = wx.TextCtrl(
            self, value="1", size=wx.Size(50, -1), style=wx.TE_PROCESS_ENTER
        )
        self.page_input.Bind(wx.EVT_TEXT_ENTER, self.OnGoToPage)
        self.pagination_sizer.Add(self.page_input, 0, wx.ALL, 5)

        self.go_button = wx.Button(self, label="Go")
        self.go_button.Bind(wx.EVT_BUTTON, self.OnGoToPage)
        self.pagination_sizer.Add(self.go_button, 0, wx.ALL, 5)

        self.next_button = wx.Button(self, label="Next")
        self.next_button.Bind(wx.EVT_BUTTON, self.OnNextPage)
        self.next_button.Disable()
        self.pagination_sizer.Add(self.next_button, 0, wx.ALL, 5)

        self.last_page_button = wx.Button(self, label=">>")
        self.last_page_button.Bind(wx.EVT_BUTTON, self.OnLastPage)
        self.last_page_button.Disable()
        self.pagination_sizer.Add(self.last_page_button, 0, wx.ALL, 5)

        self.items_per_page_choices = [25, 50, 100, 500, 1000, 10000]
        self.items_per_page_dropdown = wx.ComboBox(
            self,
            value=str(self.items_per_page),
            choices=[str(c) for c in self.items_per_page_choices],
            style=wx.CB_READONLY,
        )
        self.items_per_page_dropdown.Bind(wx.EVT_COMBOBOX, self.OnItemsPerPageChange)
        self.pagination_sizer.Add(
            wx.StaticText(self, label="Events per page:"), 0, wx.ALL | wx.CENTER, 5
        )
        self.pagination_sizer.Add(self.items_per_page_dropdown, 0, wx.ALL, 5)

        vbox.Add(self.pagination_sizer, 0, wx.CENTER | wx.BOTTOM, 5)
        self.pagination_sizer.Hide(True)

        self.resultsWindow = wx.TextCtrl(
            self, style=wx.TE_MULTILINE | wx.TE_READONLY | wx.TE_RICH2
        )
        self.resultsWindow.SetFont(FONT_CODE)
        vbox.Add(
            self.resultsWindow,
            proportion=1,
            flag=wx.EXPAND | wx.LEFT | wx.RIGHT | wx.BOTTOM,
            border=5,
        )

        self.SetSizer(vbox)
        apply_theme(self)

    def UpdateProcessButtonState(self):
        if not self.jsLogComplete and path_exists(str(GetJsLogPath(self.analysisDir))):
            self.jsLogButton.Enable()
        else:
            self.jsLogButton.Disable()

    def ProcessJsLog(self, event):
        # A busy cursor rather than a progress dialog, matching BehaviorPanel and
        # PayloadsPanel: parsing is a single pass with nothing to report part way.
        with wx.BusyCursor():
            jslog = JsLog(self.analysisDir)
            self.results["js_log"] = jslog
            self.myevents = jslog.get("events", [])
            self.LoadEventCategories()
            self.pagination_sizer.Show(True)
            self.AddTableData()
            self.grid.Show()
            self.jsLogButton.Disable()

        self.resultsWindow.SetValue(self.Summarize(jslog))
        self.jsLogComplete = True

    def Summarize(self, jslog):
        content = f'• {jslog.get("path", "")}\n'
        content += f'\tLines: {jslog.get("total_lines", 0)}\n'
        content += f'\tEvents: {jslog.get("parsed_lines", 0)}\n'
        if jslog.get("malformed_lines", 0):
            content += f'\tMalformed lines: {jslog.get("malformed_lines")}\n'
        if jslog.get("truncated", False):
            content += "\tTruncated: event limit reached, later events were not parsed.\n"
        content += "\nSelect a row to view the full event."

        return content

    def LoadEventCategories(self):
        counts = {}
        for event in self.myevents:
            name = event.get("event", "")
            counts[name] = counts.get(name, 0) + 1

        self.categoryDropdown.Clear()
        self.categoryDropdown.Append(f"{ALL_EVENTS} ({len(self.myevents)})")
        for name in sorted(counts):
            self.categoryDropdown.Append(f"{name} ({counts[name]})")
        self.categoryDropdown.SetSelection(0)
        self.category = ALL_EVENTS

    def OnCatView(self, event):
        selected = self.categoryDropdown.GetValue()
        # Labels carry a trailing " (count)" that is not part of the event name.
        self.category = selected.rsplit(" (", 1)[0]
        self.current_page = 1
        self.AddTableData()

    def GetEvents(self):
        if self.category == ALL_EVENTS:
            return self.myevents

        return [e for e in self.myevents if e.get("event", "") == self.category]

    def BodyText(self, body):
        # Body-log objects are {text, truncated} (buffered payloads add {stream, bytes, offset}).
        # Return the readable text, falling back to a string for arrays/scalars so body-bearing
        # events never render an empty cell.
        if isinstance(body, dict):
            return body.get("text") or ""
        if body is None:
            return ""
        return str(body)

    def GetSummary(self, event):
        name = event.get("event", "")
        if name in ("http_request", "http_response", "http_error"):
            parts = [
                event.get("method", ""),
                str(event.get("status", "")),
                event.get("url", ""),
                event.get("error", ""),
            ]
        elif name == "http_request_body":
            # Emitted as {request_id, body}; the body is the whole point of the event.
            parts = [self.BodyText(event.get("body"))]
        elif name in ("dns_query", "dns_result", "dns_error"):
            # The interceptor emits host/query_type/result (a body-log object), not hostname/addresses.
            parts = [
                event.get("query_type", ""),
                event.get("host", ""),
                self.BodyText(event.get("result")),
                event.get("error", ""),
            ]
        elif name in ("tcp_connect", "tcp_send", "tcp_receive", "tcp_error"):
            parts = [
                str(event.get("host", "")),
                str(event.get("port", "")),
                event.get("error", ""),
            ]
            # tcp_send/tcp_receive carry the payload inline (small text) or as a buffer-file
            # reference ({stream,bytes,offset}); js_log stamps the dropped-file sha256 onto the event.
            body = event.get("body")
            if isinstance(body, dict):
                if body.get("text"):
                    parts.append(body["text"])
                elif body.get("stream"):
                    ref = f"{body.get('bytes', 0)} bytes -> {body['stream']}"
                    if event.get("sha256"):
                        ref += f" ({event['sha256'][:12]})"
                    parts.append(ref)
        elif name == "console":
            parts = [event.get("level", ""), event.get("message", "")]
        else:
            # Everything the interceptor may add later still shows its own fields rather
            # than an empty cell.
            parts = [
                f"{key}: {value}"
                for key, value in event.items()
                if key not in ("ts", "event", "source")
            ]

        # Intercepted messages and bodies are arbitrary text. A NUL terminates the native
        # cell, dropping the rest of the summary with no error anywhere.
        summary = " ".join(str(part) for part in parts if part)
        return summary.replace("\x00", "")[:512]

    def ClearGrid(self):
        self.grid.ClearGrid()
        rows = self.grid.GetNumberRows()
        if rows > 0:
            self.grid.DeleteRows(0, rows)

    def AddTableData(self):
        myevents = self.GetEvents()
        self.numevents = len(myevents)
        self.UpdatePaginationControls()
        self.ClearGrid()

        start_index = (self.current_page - 1) * self.items_per_page
        end_index = start_index + self.items_per_page
        self.pageEvents = myevents[start_index:end_index]

        for i, event in enumerate(self.pageEvents):
            self.grid.AppendRows(1)
            self.grid.SetCellValue(i, 0, str(event.get("ts", "")))
            self.grid.SetCellValue(i, 1, str(event.get("event", "")))
            self.grid.SetCellValue(i, 2, self.GetSummary(event))

        self.grid.AutoSizeColumns()
        self.grid.AutoSizeRows()
        self.ApplyAlternateRowShading()
        self.Layout()

    def ApplyAlternateRowShading(self):
        numRows = self.grid.GetNumberRows()

        for row in range(numRows):
            if row % 2 == 0:
                attr = gridlib.GridCellAttr()
                attr.SetBackgroundColour(GRID_ROW_ALT)
                self.grid.SetRowAttr(row, attr)
        self.grid.ForceRefresh()

    def ResolveBufferedBody(self, event):
        # tcp_send/tcp_receive payloads over the inline limit are streamed to files/<sha256>; js_log
        # stamps the sha256 onto the event. Read just this chunk's slice [offset:offset+bytes] so the
        # detail pane shows the actual bytes rather than only the {stream, bytes, offset} reference.
        body = event.get("body")
        sha256 = event.get("sha256")
        if not isinstance(body, dict) or not sha256 or not body.get("stream"):
            return ""
        path = os.path.join(self.analysisDir, "files", sha256)
        if not path_exists(path):
            return ""
        try:
            offset = int(body.get("offset", 0))
            size = int(body.get("bytes", 0))
            with open(path, "rb") as fd:
                fd.seek(offset)
                raw = fd.read(size) if size else fd.read()
        except Exception:
            return ""
        return raw.decode("utf-8", errors="replace").replace("\x00", "")

    def OnSelectCell(self, event):
        row = event.GetRow()
        if 0 <= row < len(self.pageEvents):
            selected = self.pageEvents[row]
            # No NUL guard needed here: json.dumps escapes control characters, so a NUL in the
            # event data reaches the control as an escaped sequence, not a raw byte.
            content = json.dumps(selected, indent=4)
            buffered = self.ResolveBufferedBody(selected)
            if buffered:
                content += "\n\n--- buffered body ---\n" + buffered
            self.resultsWindow.SetValue(content)
        event.Skip()

    def UpdatePaginationControls(self):
        total_pages = (self.numevents + self.items_per_page - 1) // self.items_per_page
        self.page_label.SetLabel(f"Page {self.current_page} of {total_pages}")
        self.first_page_button.Enable(self.current_page > 1)
        self.prev_button.Enable(self.current_page > 1)
        self.next_button.Enable(self.current_page < total_pages)
        self.last_page_button.Enable(self.current_page < total_pages)
        self.page_input.SetValue(str(self.current_page))

        self.Layout()

    def OnPrevPage(self, event):
        if self.current_page > 1:
            self.current_page -= 1
            self.AddTableData()

    def OnNextPage(self, event):
        total_pages = (self.numevents + self.items_per_page - 1) // self.items_per_page
        if self.current_page < total_pages:
            self.current_page += 1
            self.AddTableData()

    def OnItemsPerPageChange(self, event):
        new_value = int(self.items_per_page_dropdown.GetValue())
        if new_value in self.items_per_page_choices:
            self.items_per_page = new_value
            self.current_page = 1
            self.AddTableData()

    def OnFirstPage(self, event):
        self.current_page = 1
        self.AddTableData()

    def OnLastPage(self, event):
        total_pages = (self.numevents + self.items_per_page - 1) // self.items_per_page
        self.current_page = total_pages
        self.AddTableData()

    def OnGoToPage(self, event):
        total_pages = (self.numevents + self.items_per_page - 1) // self.items_per_page
        try:
            page_num = int(self.page_input.GetValue())
            if 1 <= page_num <= total_pages:
                self.current_page = page_num
                self.AddTableData()
            else:
                wx.MessageBox(
                    f"Page number must be between 1 and {total_pages}.",
                    "Invalid Page Number",
                    wx.OK | wx.ICON_ERROR,
                )
        except ValueError:
            wx.MessageBox(
                "Please enter a valid integer page number.",
                "Invalid Input",
                wx.OK | wx.ICON_ERROR,
            )
