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
- [ ] DPI. Check at 100%, 150% and 200% scaling. `classes/status_bar.py` still
      uses hardcoded pixels (`BAR_HEIGHT`, `COUNTDOWN_WIDTH`, `PADDING`); they
      need `theme.dip()`.
- [ ] Fonts. `theme._resolve_face()` picks the first installed face from a
      preference list; confirm it lands on Segoe UI / Cascadia Mono and not a
      fallback.
- [ ] `ui_kit.Picker` popup placement and dismissal on a multi-monitor setup.

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

## Deferred cleanup

- [ ] `FlatNotebook` is no longer used by any panel; only the styling branch in
      `classes/theme.py` still references it. Delete it.
- [ ] `classes/status_bar.py`: hardcoded pixel constants -> `theme.dip()`.
