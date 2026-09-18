#!/usr/bin/env python3
"""Headless interaction smoke test for the reworked Start tab.

Layout is checked with screenshots; this checks the things a screenshot cannot: that the
replaced controls still answer the API the rest of the panel calls, that the option string
the analyzer receives is unchanged, and that toggling the theme or a disclosure pane does
not throw. Run under xvfb-run.
"""

import sys
import traceback
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import shoot  # noqa: E402  - installs the stubs and the working directory
import wx  # noqa: E402

FAILURES = []


def check(name, condition, detail=""):
    status = "ok  " if condition else "FAIL"
    if not condition:
        FAILURES.append(f"{name}: {detail}")
    print(f"[{status}] {name}{(' - ' + detail) if detail and not condition else ''}")


def run():
    app = wx.App()
    from CAPEsolo.classes import theme
    from CAPEsolo.classes import ui_kit as ui
    from CAPEsolo.classes.start_panel import StartPanel

    theme._init()
    theme.set_theme("dark")

    # The broker pops a modal password dialog through CallAfter; a headless run must not
    # block on it.
    StartPanel._InitDownloadBroker = lambda self: None

    frame = shoot.target_frame(app, wx.Size(1400, 900))
    frame.Show()
    shoot._flush(app, 3)
    start = frame.startTab

    # -- the controls still speak the API the panel calls --------------------
    check("target path is a TextCtrl", isinstance(start.targetPath, wx.TextCtrl))
    start.targetPath.SetValue("C:/samples/evil.exe")
    check("target path round-trips", start.targetPath.GetValue() == "C:/samples/evil.exe")

    # Only "Auto-detect" is present off Windows: PackageDropdown lists modules\\packages,
    # a path that does not resolve here. The API is what is under test, not the contents.
    check("package picker populated", start.packageDropdown.GetCount() >= 1)
    start.packageDropdown.Append("exe")
    start.packageDropdown.SetValue("exe")
    check("package selection round-trips", start.packageDropdown.GetValue() == "exe")
    start.packageDropdown.SetValue("Auto-detect")
    check("package resets to Auto-detect", start.packageDropdown.GetValue() == "Auto-detect")

    check("help list populated", start.helpList.GetCount() > 10)
    check("help list defaults to header", start.helpList.GetStringSelection() == "Options Help")

    # -- the values AddTargetOptions turns into the analyzer's option string --
    # Asserted at this level rather than by calling AddTargetOptions, which writes
    # analysis.conf and starts a run. These are the exact expressions it evaluates.
    start.free.SetValue(False)
    start.logExceptions.SetValue(True)
    start.logExceptionsLevel.Enable(True)
    start.logExceptionsLevel.SetSelection(1)
    start.traceTimes.SetValue(True)
    for radio, option in start.hookSets:
        radio.SetValue(option == "minhook")

    hooks = [option for radio, option in start.hookSets if option and radio.GetValue()]
    check("exactly one hook set emitted", hooks == ["minhook"], f"got {hooks}")

    emitted = []
    for box, name, level in start.loggingOptions:
        if box.GetValue():
            value = level.GetStringSelection().split(" ", 1)[0] if level else "1"
            emitted.append(f"{name}={value}")
    check(
        "levelled and boolean log options emit correctly",
        emitted == ["log-exceptions=2", "trace-times=1"],
        f"got {emitted}",
    )

    check(
        "unhook-on-terminate reads back",
        start.unhookOnExit.GetValue() is True,
    )
    check("timeout field parses", int(start.timeoutInput.GetValue()) == 200)

    # -- disclosure panes ----------------------------------------------------
    for pane, label in (
        (start.debuggerCollapsePane, "debugger"),
        (start.analysisConfExpander, "analysis.conf"),
    ):
        check(f"{label} starts collapsed", pane.IsCollapsed())
        pane.Toggle()
        shoot._flush(app, 2)
        check(f"{label} expands", not pane.IsCollapsed())
        check(f"{label} pane is shown", pane.GetPane().IsShown())
        pane.Toggle()
        shoot._flush(app, 2)
        check(f"{label} collapses again", pane.IsCollapsed())

    # -- radio grouping ------------------------------------------------------
    radios = [radio for radio, _ in start.hookSets]
    radios[2].SetValue(True)
    selected = [index for index, radio in enumerate(radios) if radio.GetValue()]
    check("hook radios are mutually exclusive", selected == [2], f"selected={selected}")

    # -- picker popup --------------------------------------------------------
    start.packageDropdown.ShowPopup()
    shoot._flush(app, 2)
    check("picker popup opens", start.packageDropdown._popup is not None)
    start.packageDropdown._popup.Dismiss()
    shoot._flush(app, 2)
    check("picker popup dismisses", start.packageDropdown._popup is None)

    # -- button events still reach their handlers ----------------------------
    fired = []
    start.jsonReportBtn.Enable(True)
    start.jsonReportBtn.Bind(wx.EVT_BUTTON, lambda event: fired.append(True))
    start.jsonReportBtn._Fire()
    check("button emits EVT_BUTTON", fired == [True])

    # -- theme switch --------------------------------------------------------
    frame.RefreshTheme()
    shoot._flush(app, 2)
    check("theme switched to light", not theme.is_dark())
    frame.RefreshTheme()
    shoot._flush(app, 2)
    check("theme switched back to dark", theme.is_dark())

    # -- tab switching -------------------------------------------------------
    for index in range(frame.notebook.GetPageCount()):
        frame.notebook.SetSelection(index)
        shoot._flush(app, 1)
    check("all tabs render", frame.notebook.GetSelection() == frame.notebook.GetPageCount() - 1)
    frame.notebook.SetSelection(0)

    # -- themed message dialog ----------------------------------------------
    from CAPEsolo.classes import ui_kit as ui

    labels = lambda style: [action[1] for action in ui._MessageDialog._Actions(style)]
    check("OK style yields one button", labels(wx.OK) == ["OK"])
    check("YES_NO replaces OK", labels(wx.YES_NO) == ["Yes", "No"])
    check("CANCEL is additive", labels(wx.YES_NO | wx.CANCEL) == ["Yes", "No", "Cancel"])

    defaults = [action[0] for action in ui._MessageDialog._Actions(wx.YES_NO) if action[3]]
    check("Yes is the default", defaults == [wx.ID_YES])
    defaults = [
        action[0] for action in ui._MessageDialog._Actions(wx.YES_NO | wx.NO_DEFAULT) if action[3]
    ]
    check("NO_DEFAULT moves the default", defaults == [wx.ID_NO])

    badges = ui._MessageDialog._Kind
    check("error icon maps to a badge", badges(wx.OK | wx.ICON_ERROR) == ui._BADGE_ERROR)
    check("no icon flag means no badge", badges(wx.OK) is None)

    # Drive a real modal loop: the dialog has to close on its own or the harness hangs.
    for style, press, expected, name in (
        (wx.OK | wx.ICON_ERROR, wx.ID_OK, wx.OK, "OK"),
        (wx.YES_NO | wx.ICON_QUESTION, wx.ID_YES, wx.YES, "Yes"),
        (wx.YES_NO | wx.ICON_QUESTION, wx.ID_NO, wx.NO, "No"),
        (wx.YES_NO | wx.CANCEL, wx.ID_CANCEL, wx.CANCEL, "Cancel"),
    ):
        holder = {}

        def press_button(press=press, holder=holder):
            dialog = holder.get("dialog")
            if dialog is not None:
                dialog.EndModal(press)

        original = ui._MessageDialog.ShowModal

        def capture(self, original=original, holder=holder):
            holder["dialog"] = self
            wx.CallLater(30, press_button)
            return original(self)

        ui._MessageDialog.ShowModal = capture
        try:
            got = ui.message("Harness", "Harness", style)
        finally:
            ui._MessageDialog.ShowModal = original
        check(f"message() returns wx.{name}", got == expected, f"got {got}")

    frame.Destroy()
    app.Yield()


if __name__ == "__main__":
    try:
        run()
    except Exception:
        traceback.print_exc()
        FAILURES.append("unhandled exception")

    print()
    if FAILURES:
        print(f"{len(FAILURES)} failure(s):")
        for failure in FAILURES:
            print("  -", failure)
        sys.exit(1)
    print("all checks passed")
