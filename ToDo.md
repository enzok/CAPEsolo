# ToDo

## Windows verification (GUI modernization)

The GUI rework on `gui-modernize` was written and rendered on **wxGTK 4.2.4
(wxWidgets 3.2.9) under Xvfb on Linux**. The owner-drawn controls in
`classes/ui_kit.py` are platform-neutral, but nothing below has been seen on
wxMSW. All of it needs a pass on a real Windows box.

### Environment

- [ ] Confirm the installed wxPython is **>= 4.3.0** (`python -c "import wx; print(wx.version())"`).
      `pyproject.toml` pins it; the Linux dev box only had 4.2.4, which lacks the
      dark mode opt-in below.

### Native dark mode opt-in

`CapesoloApp._EnableNativeDarkMode()` in `CAPEsolo/cli.py` calls
`wx.App.MSWEnableDarkMode()` before the first window is created. It covers the
widgets we cannot owner-draw: scrollbars, native menus, tooltips, the grid cell
editor and the common dialogs. It is guarded with `getattr`, so on 4.2.x and on
GTK it silently does nothing.

- [ ] Confirm the method exists at runtime and is actually called (it is skipped
      when the light palette is active).
- [ ] Confirm the enum resolution picked a real constant. The code probes
      `wx.MSW_DARK_MODE_ALWAYS` then `wx.App.DarkMode_Always`; if neither exists
      it falls back to the no-argument call, which follows the *system* theme
      rather than forcing dark. Fix the name once the real one is known.
- [ ] Check what it fixes and what it misses. Known upstream gap: some
      TaskDialog-based dialogs still render light.
- [ ] Scrollbars in the Start tab and in every grid.
- [ ] Right-click menus (`custom_grid.py`, `process_tree_window.py`,
      `patch_dialog.py`, `debug_controls.py`, `start_panel.py`).
- [ ] Grid cell editor (double-click a cell in Configs / Payloads / Yara /
      Network / PE) - the in-place editor is a native `wx.TextCtrl`.
- [ ] Decide whether a theme toggle should prompt for a restart. The opt-in
      cannot be reversed once windows exist, so toggling light -> dark leaves the
      native widgets light until the next launch.

### Rendering

- [ ] Screenshot every tab in both palettes and compare against the GTK renders.
- [ ] Disabled states. Native MSW controls ignore `SetForegroundColour` when
      disabled, which is what made the old UI illegible. Any widget that is still
      native and gets `Disable()`d will show the same grey-on-grey.
- [ ] DPI. Check at 100%, 150% and 200% scaling. The geometry was verified on
      Linux by forcing `theme.dip()` to 2x (padding, radii, the tab indicator and
      the status bar all scale, nothing clips), but `FromDIP` returns the real
      scale only on a display that has one.
- [ ] Fonts. `theme._resolve_face()` picks the first installed face from a
      preference list; confirm it lands on Segoe UI / Cascadia Mono and not a
      fallback.
- [ ] `ui_kit.Picker` popup placement and dismissal on a multi-monitor setup.
- [ ] `ListCtrl` column headers. Under GTK the header renders dark even on the
      light palette - it is drawn by the toolkit, not by us. On wxMSW it is a
      native header control; check whether it follows `MSWEnableDarkMode` or
      stays light against the dark palette (Exports, Patch History, and every
      debugger list).
- [ ] Control borders. `BORDER_STRONG` was raised in both palettes to clear 3:1
      against the card, which is what outlines fields and pickers. Confirm it
      reads as an outline and not as a heavy box on MSW.

### Functional

- [ ] One real analysis: pick a target, Launch, let it run, Kill, then
      Auto-process and open the reports. The Start tab layout changed
      (`StartPanel` is now a `wx.Panel` wrapping a `ScrolledPanel`) and
      `cli.py` still reads `frame.startTab.GetSizer().GetMinSize()` at startup to
      widen the frame - confirm that still produces a sane width.
- [ ] The analyzer option string. `AddTargetOptions()` now reads ui_kit controls;
      the headless smoke test covers it, but confirm against a live capemon run.
- [ ] Debugger tab: breakpoint rows are `ui.Picker` / `ui.Field` now.
- [ ] `DownloadKeysDialog` - it is raised from `_InitDownloadBroker` via
      `CallAfter` at startup and is modal.
- [ ] Dialog buttons. `ui.dialog_buttons()` relies on wxDialog's built-in
      wxID_OK / wxID_CANCEL handling firing for owner-drawn buttons. Verified on
      GTK, including a dialog-level handler refusing to close; confirm on MSW for
      the patch, breakpoint, prototype and credentials dialogs.

### Accessibility and keyboard

`ui_kit` attaches a `wx.Accessible` to each control so screen readers get a role,
a name and a state instead of "window". None of it can be exercised on the dev
box: wxGTK is built without `wxUSE_ACCESSIBILITY`, so `wx.Accessible()` raises
`NotImplementedError` and the code latches the whole layer off. **MSAA is
therefore completely unverified.**

- [ ] Run NVDA (or Narrator) over the Start tab. Every button, checkbox, radio
      button, picker, tab and card should announce its role and its state.
- [ ] Confirm `_PickerAccessible` declining its name is right on MSW - it is meant
      to let the reader fall back to the neighbouring "Package" / "Path:" label.
- [ ] Confirm the tab strip reports as a page tab list with the open tab selected.
- [ ] Mnemonics. `&Launch` underlines the L and Alt+L activates it. On MSW the
      underline is usually hidden until Alt is pressed; ours is always drawn.
      Decide whether to follow the platform convention.
- [ ] Tab order through the Start tab and the dialogs. Not verified anywhere -
      Xvfb has no window manager to drive focus.
- [ ] High-contrast mode. Windows overrides system colours; the app draws its own,
      so it will ignore the setting entirely. Decide whether that is acceptable.

### Rendering (continued)

- [ ] Glyphs. They are stroked from a vector table at paint time with a 1.6 DIP
      pen. Check they do not turn muddy at 100% scaling on a real display, and
      that the filled ones (play, stop, settings) read correctly at 14 DIP.
- [ ] `ui.Notice`. The empty states are laid out for a results pane; confirm the
      wrapped detail line does not clip in a narrow window.

## Tooling

`tools/uidev/` builds the UI off screen under Xvfb and is wired into CI
(`.github/workflows/ci.yml`). It is a Linux/GTK approximation by construction.

- [ ] Re-shoot the visual regression baseline on Windows, or record that the
      baseline is GTK-only. `vrt.py --update` re-records; the shots carry the font
      stack of whichever machine took them.
- [ ] Decide whether the `ui` CI job should gate on `vrt.py` once the baseline is
      stable. It is `continue-on-error` today and only uploads the renders.

## Deferred cleanup

- [x] `FlatNotebook` styling branch deleted from `classes/theme.py`.
- [x] `classes/status_bar.py`: pixel constants now go through `theme.dip()`.
- [x] `wx.Button = buttons.GenButton` monkeypatch removed from `cli.py`, along with
      the label-sniffing colour heuristic in `theme.py` it fed.
- [x] Raw pixel literals in the panels replaced with the `SP_*` spacing scale.
