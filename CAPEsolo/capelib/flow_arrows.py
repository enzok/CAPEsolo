"""Branch arrow gutter for the interactive debugger's disassembly view.

Lays out jump arrows as box-drawing text, one string per row, for a fixed-width monospace
column. Pure functions on plain tuples, free of wx and pipe imports so the layout can be
exercised without a GUI (see tests/test_flow_arrows.py).

Text rather than drawn lines because the disassembly is a native wxMSW wx.ListCtrl, which
does not expose per-item custom drawing: real graphics would mean replacing the control.
Every glyph below is present in Consolas, the theme's code font, at the same advance width as
an ASCII character, so the column stays aligned.
"""


import re

VERTICAL = "│"    # |
HORIZONTAL = "─"  # -
CORNER_DOWN = "┌" # ,-
CORNER_UP = "└"   # '-
CROSS = "┼"       # +
HEAD = "►"        # >
OFF_UP = "▲"      # ^ target above the decoded window
OFF_DOWN = "▼"    # v target below the decoded window

# Conditional and unconditional jumps, and the loop family. Calls are deliberately absent:
# they return, so an arrow to every call target would fill the gutter without saying anything
# about control flow within the function being read.
JUMP_RX = re.compile(
    r"^\s*(?:j(?:mp|[a-z]{1,3})|loop(?:n?[ez])?)\s+(?:[A-Za-z_]+\s+)*?(0x[0-9A-Fa-f]+)\s*$",
    re.IGNORECASE,
)
# Lanes before arrows start being dropped. Three is about what stays legible in a character
# cell grid; past that the gutter is noise.
MAX_LANES = 3
# Lanes plus the column the arrow head sits in, against the address.
GUTTER_WIDTH = MAX_LANES + 1


def JumpTarget(text: str) -> int | None:
    """The address a jump goes to, or None if this is not a direct jump.

    An indirect jump has no target until its memory is read, and a call is not a branch for
    this purpose, so both answer None.
    """
    m = JUMP_RX.match(text)
    return int(m.group(1), 16) if m else None


def _Write(row: list[str], index: int, glyph: str) -> None:
    """Place `glyph`, turning a line that crosses another into a cross rather than cutting it."""
    current = row[index]
    if glyph == HORIZONTAL and current in (VERTICAL, CROSS):
        row[index] = CROSS
    elif glyph == VERTICAL and current in (HORIZONTAL, CROSS):
        row[index] = CROSS
    else:
        row[index] = glyph


def BranchLanes(instructions) -> list[str]:
    """One gutter string per instruction, describing the jumps between them.

    `instructions` needs `.address` and `.text` per entry, which is what DecodedInstruction
    provides. Arrows are assigned innermost-first by span, so a tight loop sits next to the
    address column and a long jump is pushed out - the reading order an analyst expects.

    A jump whose target is outside the decoded window cannot be drawn, so its row is marked
    with the direction it leaves in instead. That is the case the gutter is most useful for:
    the instruction text already names an address, but not whether it is behind you.
    """
    rowOf = {inst.address: i for i, inst in enumerate(instructions)}
    spans = []
    markers = {}
    for src, inst in enumerate(instructions):
        target = JumpTarget(inst.text)
        if target is None:
            continue

        dst = rowOf.get(target)
        if dst is None:
            markers[src] = OFF_UP if target < inst.address else OFF_DOWN
        elif dst != src:
            spans.append((abs(dst - src), src, dst))

    # Shortest span first, so the innermost lane goes to the tightest jump. Ties break on
    # source row to keep the layout stable between two decodes of the same bytes.
    spans.sort(key=lambda span: (span[0], span[1]))

    grid = [[" "] * GUTTER_WIDTH for _ in instructions]
    laneEnds: list[int] = []
    placed = []
    for _span, src, dst in spans:
        top, bottom = min(src, dst), max(src, dst)
        lane = next((i for i, end in enumerate(laneEnds) if end < top), None)
        if lane is None:
            if len(laneEnds) == MAX_LANES:
                # Out of lanes. Mark the direction rather than dropping the jump silently:
                # the row would otherwise look like it does not branch at all.
                markers[src] = OFF_DOWN if dst > src else OFF_UP
                continue

            lane = len(laneEnds)
            laneEnds.append(bottom)
        else:
            laneEnds[lane] = bottom

        placed.append((lane, src, dst))

    # Outermost lane first, so an inner arrow's corner is never overwritten by an outer
    # arrow's horizontal run.
    for lane, src, dst in sorted(placed, key=lambda item: -item[0]):
        column = MAX_LANES - 1 - lane
        top, bottom = min(src, dst), max(src, dst)
        for row in range(top + 1, bottom):
            _Write(grid[row], column, VERTICAL)

        _Write(grid[top], column, CORNER_DOWN)
        _Write(grid[bottom], column, CORNER_UP)
        for end in (top, bottom):
            for index in range(column + 1, GUTTER_WIDTH):
                _Write(grid[end], index, HORIZONTAL)

        grid[dst][GUTTER_WIDTH - 1] = HEAD

    # Only where the head column is free: a row can both be jumped to and itself jump
    # somewhere undrawable, and an arrow that was actually drawn is worth more than a marker.
    for row, glyph in markers.items():
        if grid[row][GUTTER_WIDTH - 1] == " ":
            grid[row][GUTTER_WIDTH - 1] = glyph

    return ["".join(row) for row in grid]
