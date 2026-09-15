"""Tests for the disassembly view's branch arrow gutter.

CAPEsolo.capelib.flow_arrows is deliberately free of wx and pipe imports so these run without
a GUI, a monitor, or a live analysis:

    ./.venv/Scripts/python.exe -m pytest tests/test_flow_arrows.py
"""

from collections import namedtuple

from CAPEsolo.capelib.flow_arrows import (
    CORNER_DOWN,
    CORNER_UP,
    CROSS,
    GUTTER_WIDTH,
    HEAD,
    HORIZONTAL,
    MAX_LANES,
    OFF_DOWN,
    OFF_UP,
    VERTICAL,
    BranchLanes,
    JumpTarget,
)

Inst = namedtuple("Inst", ["address", "text"])


def Block(texts, base=0x1000, step=2):
    """Instructions at `step` bytes apart, so row N is at base + N * step."""
    return [Inst(base + i * step, text) for i, text in enumerate(texts)]


def test_jump_target_reads_direct_jumps():
    assert JumpTarget("JMP 0x401000") == 0x401000
    assert JumpTarget("JE 0x401000") == 0x401000
    assert JumpTarget("JNZ 0x401000") == 0x401000
    assert JumpTarget("LOOP 0x401000") == 0x401000
    assert JumpTarget("LOOPNE 0x401000") == 0x401000


def test_jump_target_ignores_everything_that_is_not_a_direct_jump():
    # A call returns, so it is not control flow worth an arrow.
    assert JumpTarget("CALL 0x401000") is None
    # Indirect: no target until the memory is read.
    assert JumpTarget("JMP QWORD [RIP+0x3af9]") is None
    assert JumpTarget("JMP QWORD [RAX+0x8]") is None
    assert JumpTarget("MOV RAX, 0x401000") is None
    assert JumpTarget("PUSH RBP") is None
    # An operand already replaced by a symbol is not an address any more.
    assert JumpTarget("JMP kernel32!VirtualAlloc") is None


def test_gutter_is_blank_when_nothing_branches():
    gutter = BranchLanes(Block(["PUSH RBP", "MOV RBP, RSP", "POP RBP"]))
    assert gutter == [" " * GUTTER_WIDTH] * 3


def test_every_row_gets_a_string_of_the_same_width():
    gutter = BranchLanes(Block(["JMP 0x1006", "NOP", "NOP", "NOP"]))
    assert len(gutter) == 4
    assert {len(row) for row in gutter} == {GUTTER_WIDTH}


def test_backward_jump_draws_a_loop():
    """The case the gutter exists for: seeing at a glance that this is a loop."""
    # rows: 0 NOP, 1 NOP, 2 JMP back to row 1 (0x1002)
    gutter = BranchLanes(Block(["NOP", "NOP", "JMP 0x1002"]))
    lane = MAX_LANES - 1
    assert gutter[0][lane] == " "
    assert gutter[1][lane] == CORNER_DOWN
    assert gutter[2][lane] == CORNER_UP
    # Head sits against the address column, on the row jumped to.
    assert gutter[1][-1] == HEAD
    assert gutter[2][-1] == HORIZONTAL


def test_forward_jump_head_is_on_the_target_row():
    # rows: 0 JE to row 3 (0x1006), 1 NOP, 2 NOP, 3 NOP
    gutter = BranchLanes(Block(["JE 0x1006", "NOP", "NOP", "NOP"]))
    lane = MAX_LANES - 1
    assert gutter[0][lane] == CORNER_DOWN
    assert gutter[3][lane] == CORNER_UP
    assert gutter[1][lane] == VERTICAL
    assert gutter[2][lane] == VERTICAL
    assert gutter[3][-1] == HEAD
    assert gutter[0][-1] == HORIZONTAL


def test_tightest_jump_gets_the_innermost_lane():
    """A long jump must not sit between a short one and the code it points at."""
    # row 0 jumps to row 5 (long), row 2 jumps to row 3 (short)
    gutter = BranchLanes(Block(["JMP 0x100a", "NOP", "JE 0x1006", "NOP", "NOP", "NOP"]))
    inner, outer = MAX_LANES - 1, MAX_LANES - 2
    assert gutter[2][inner] == CORNER_DOWN   # short jump, innermost
    assert gutter[0][outer] == CORNER_DOWN   # long jump, pushed out
    assert gutter[5][outer] == CORNER_UP


def test_crossing_arrows_are_drawn_as_a_cross_not_a_break():
    """An outer arrow's horizontal run crosses an inner lane; the inner line must survive.

    An if/else: the outer arrow skips the whole else branch and lands on row 5, where the
    inner arrow (the jump over the else) is still running. The outer arrow's run to the head
    column passes straight through the inner lane.
    """
    gutter = BranchLanes(
        Block(["TEST EAX, EAX", "JE 0x100a", "MOV EAX, 0x1", "JMP 0x100c", "NOP", "MOV EAX, 0x2", "RET"])
    )
    outer, inner = MAX_LANES - 2, MAX_LANES - 1
    assert gutter[5][outer] == CORNER_UP  # outer arrow ends here
    assert gutter[5][inner] == CROSS      # ...crossing the inner arrow, which continues
    assert gutter[5][-1] == HEAD
    assert gutter[6][inner] == CORNER_UP  # inner arrow still ends a row later, uncut


def test_lanes_are_reused_once_an_arrow_has_ended():
    """Two jumps that do not overlap share the innermost lane rather than stacking."""
    gutter = BranchLanes(Block(["JMP 0x1002", "NOP", "JMP 0x1008", "NOP", "NOP"]))
    inner = MAX_LANES - 1
    assert gutter[0][inner] == CORNER_DOWN
    assert gutter[2][inner] in (CORNER_DOWN, CORNER_UP, CROSS)
    # Nothing was pushed to an outer lane.
    assert all(row[: MAX_LANES - 1] == " " * (MAX_LANES - 1) for row in gutter)


def test_arrows_beyond_the_lane_cap_are_marked_not_drawn():
    """An undrawable jump still has to look like a jump, or the row reads as straight-line."""
    # Five jumps over the same rows to row 11 (0x1016); only MAX_LANES can be drawn.
    gutter = BranchLanes(Block(["JMP 0x1016"] * 5 + ["NOP"] * 7))
    used = {i for row in gutter for i, ch in enumerate(row[:MAX_LANES]) if ch != " "}
    assert len(used) <= MAX_LANES
    # The two that missed out say which way they go instead of showing nothing.
    assert gutter[0][-1] == OFF_DOWN
    assert gutter[1][-1] == OFF_DOWN


def test_a_drawn_head_is_not_overwritten_by_a_marker():
    """A row can be both jumped to and itself jump off-window; the real arrow wins."""
    # row 1 is the target of row 0's jump, and itself jumps outside the window.
    gutter = BranchLanes(Block(["JMP 0x1002", "JMP 0x99000", "NOP"]))
    assert gutter[1][-1] == HEAD


def test_target_above_the_window_is_marked_not_drawn():
    gutter = BranchLanes(Block(["NOP", "JMP 0x400"]))
    assert gutter[1][-1] == OFF_UP
    assert gutter[0] == " " * GUTTER_WIDTH


def test_target_below_the_window_is_marked_not_drawn():
    gutter = BranchLanes(Block(["JMP 0x99000", "NOP"]))
    assert gutter[0][-1] == OFF_DOWN


def test_jump_to_itself_is_not_an_arrow():
    # An infinite self-loop has nowhere to point; a zero-length arrow would draw as a stray
    # corner on its own row.
    gutter = BranchLanes(Block(["JMP 0x1000"]))
    assert gutter == [" " * GUTTER_WIDTH]


def test_empty_input():
    assert BranchLanes([]) == []
