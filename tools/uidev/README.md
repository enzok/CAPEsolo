# uidev - UI development harness

CAPEsolo runs on Windows, but its layout and drawing code is wxPython, which renders the
same way under GTK. These scripts build the real panels off screen on a Linux box so a UI
change can be reviewed as a picture, and so a broken panel is caught without a VM.

Nothing here is imported by the application. It is developer tooling and is not shipped in
the wheel.

## Requirements

* wxPython 4.2+ (`apt install python3-wxgtk4.0` or a pip wheel).
* `xvfb` for the off-screen X server (`apt install xvfb`).
* Nothing else. The Windows-only and heavyweight imports (pywin32, bson, gevent, sflock,
  yara) are answered by `winstubs.py`, so no CAPEsolo runtime dependency has to be
  installed.

## Scripts

### `smoke.py` - does every panel still build?

```
xvfb-run -a python3 tools/uidev/smoke.py
```

Constructs MainFrame and each result panel in both themes, switches the theme at runtime,
opens the dialogs, and reports the first exception with a traceback. Exit code is non-zero
on failure. Takes about 35 s. This is the check to run after any widget change.

### `shoot.py` - render one target to a PNG

```
xvfb-run -a python3 tools/uidev/shoot.py frame --theme dark -o /tmp/frame.png
xvfb-run -a python3 tools/uidev/shoot.py yara  --theme light --size 1180x800 -o /tmp/yara.png
```

Targets: `frame`, `start`, `gallery`, and one per result panel (`behavior`, `configs`,
`debugger`, `js`, `network`, `payloads`, `signatures`, `strings`, `target`, `yara`).

A segfault printed *after* the path line is a wxGTK teardown artifact under Xvfb; the PNG
is already written. Filter it with `| grep -vi segmentation` in scripts.

### `gallery.py` - the ui_kit specimen sheet

Not run directly - it is the `gallery` target of `shoot.py`. Every `ui_kit` primitive in
every state (idle/hover/disabled, checked/unchecked, expanded/collapsed, all three notice
kinds, every glyph) on one page, so a change to the drawing code is checked at a glance.

GTK will not make a window taller than the monitor work area, so the full sheet does not
fit in one capture. `UIDEV_SECTIONS` selects a subset:

```
UIDEV_SECTIONS=glyphs,states xvfb-run -a python3 tools/uidev/shoot.py gallery \
    --size 1180x520 -o /tmp/glyphs.png
```

Sections: `tabs`, `buttons`, `glyphs`, `toggles`, `inputs`, `states`, `surfaces`.

### `vrt.py` - visual regression

```
xvfb-run -a python3 tools/uidev/vrt.py            # compare against tools/uidev/baseline
xvfb-run -a python3 tools/uidev/vrt.py --update   # re-record the baseline
```

Renders the shot list in `vrt.py`, compares each PNG with the recorded baseline pixel by
pixel, and writes the changed pixels to `--out` (default `/tmp/capesolo-vrt`) as a red-on-
grey diff image. Exit code is non-zero if any shot moved by more than `--tolerance`
(default 0.1% of pixels).

The baseline is recorded on one machine's font stack. A different GTK theme, font package
or DPI will shift text by a pixel and light the whole thing up, so **a mismatch is a prompt
to look at the diff image, not a failure on its own**. This is why CI does not gate on it -
CI renders the same shots and uploads them as artifacts instead.

### `dpishot.py` - fake a HiDPI display

```
xvfb-run -a python3 tools/uidev/dpishot.py frame -o /tmp/frame-2x.png
```

`GDK_SCALE` does nothing under Xvfb, so this multiplies what `theme.dip()` returns and
scales every font in `theme._FONTS` instead. It catches hardcoded pixel values that would
not scale on a 150%/200% Windows display. It is an approximation of wxMSW's DPI handling,
not a substitute for looking at a real HiDPI machine.

### `winstubs.py`

The import hook the other scripts install. Appended to the end of `sys.meta_path`, so it
only sees modules that every real finder already declined. `CAPEsolo`, `wx` and `msvcrt`
are never stubbed - the first two must fail loudly, and stubbing `msvcrt` makes the
stdlib's `subprocess` take its Windows path and then fail to find `_winapi`.

## Caveats

* Native controls (combo popups, grid scrollbars, the ListCtrl header) are drawn by GTK
  here and by Windows there. Everything `ui_kit` draws is identical on both.
* `PackageDropdown()` lists `modules\packages`, a Windows path, so the package picker only
  ever offers "Auto-detect" in a render. Harness artifact, not a bug.
* The harness writes its config to a temp directory (`CAPESOLO_CFG`), so a run cannot
  touch a real `cfg.ini`.
