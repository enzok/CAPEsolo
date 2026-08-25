"""Shared VirusTotal helpers for the Info and Payloads tabs.

vt_lookup/vt_upload do blocking network calls, so they run on a daemon thread and the result is
marshalled back to the UI thread with wx.CallAfter - the same pattern start_panel uses for downloads.
Only the embedded public key is ever used; the private/encrypted key is never touched here.
"""

from pathlib import Path
from threading import Thread

import wx

from CAPEsolo.capelib.virustotal import vt_lookup, vt_upload


def run_vt_lookup_async(sha256, on_done):
    """Look up *sha256* off the UI thread and deliver the result dict via on_done(result)."""

    def worker():
        result = vt_lookup(sha256)
        wx.CallAfter(on_done, result)

    Thread(target=worker, daemon=True).start()


def run_vt_upload_async(path, sha256, on_done):
    """Upload *path* off the UI thread and deliver the result dict via on_done(result)."""

    def worker():
        result = vt_upload(str(path), sha256 or "")
        wx.CallAfter(on_done, result)

    Thread(target=worker, daemon=True).start()


def confirm_vt_upload(window, path):
    """Confirm a publish to VirusTotal. Returns True only if the user explicitly agrees."""
    msg = (
        f"Upload '{Path(path).name}' to VirusTotal?\n\n"
        "The file will be sent to VirusTotal and become publicly downloadable to their "
        "community. This cannot be undone."
    )
    return (
        wx.MessageBox(msg, "Upload to VirusTotal", wx.YES_NO | wx.ICON_WARNING, window) == wx.YES
    )


def format_vt_rows(result):
    """Compact (label, value) rows for a vt_lookup result. Error dicts return [] (caller shows msg)."""
    if result.get("error"):
        return []
    if not result.get("found"):
        return [("VirusTotal", "Not found")]

    rows = []
    if not result.get("summary") and not result.get("detection"):
        rows.append(("VirusTotal", "Present, analysis pending"))
    candidates = [
        ("VT Detections", result.get("summary")),
        ("VT Detection", result.get("detection")),
        ("VT First Seen", result.get("first_seen")),
        ("VT Last Seen", result.get("last_seen")),
        ("VT Link", result.get("permalink")),
    ]
    rows.extend((label, str(value)) for label, value in candidates if value)
    return rows
