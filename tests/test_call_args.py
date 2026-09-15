"""Tests for the disassembly view's call argument annotation.

CAPEsolo.capelib.call_args is deliberately free of wx and pipe imports so these run without
a GUI, a monitor, or a live analysis:

    ./.venv/Scripts/python.exe -m pytest tests/test_call_args.py
"""

from CAPEsolo.capelib.call_args import (
    X86_ARG_COUNT,
    CallArguments,
    ParseRegisters,
)

# The shape FormatRegisters writes in capemon: name, colon, padded hex, then a flag field.
REGS_64 = (
    "RAX: 0000000000000000    CF:0\n"
    "RCX: 0000000000000000    PF:0\n"
    "RDX: 0000000000021000    AF:0\n"
    "RSP: 000000000014FF28    ZF:1\n"
    "R8 : 0000000000003000    SF:0\n"
    "R9 : 0000000000000040    TF:0\n"
    "RIP: 0000000140001374  IOPL:0\n"
)
REGS_32 = "EAX: 00000000    CF:0\nESP: 0014FF28    PF:0\nEIP: 00401374    ZF:1\n"


def test_parse_registers_reads_the_pane():
    regs = ParseRegisters(REGS_64)
    assert regs["rcx"] == 0
    assert regs["rdx"] == 0x21000
    assert regs["rsp"] == 0x14FF28
    assert regs["rip"] == 0x140001374


def test_parse_registers_handles_the_padded_short_names():
    """capemon writes "R8 :" with a space to keep the column aligned."""
    regs = ParseRegisters(REGS_64)
    assert regs["r8"] == 0x3000
    assert regs["r9"] == 0x40


def test_parse_registers_on_empty_text():
    assert ParseRegisters("") == {}


def test_x64_arguments_come_from_the_abi_registers_in_order():
    args = CallArguments(64, ParseRegisters(REGS_64), [])
    assert [name for name, _ in args] == ["RCX", "RDX", "R8", "R9"]
    assert [value for _, value in args] == [0, 0x21000, 0x3000, 0x40]


def test_x64_needs_no_stack():
    """The first four are in registers, so a missing stack window is not a problem."""
    assert len(CallArguments(64, ParseRegisters(REGS_64), [])) == 4


def test_x64_with_registers_missing_reports_what_it_has():
    args = CallArguments(64, {"rcx": 1, "r8": 3}, [])
    assert args == [("RCX", 1), ("R8", 3)]


def test_x86_arguments_are_read_from_the_stack_pointer_up():
    sp = 0x14FF28
    stack = [(sp - 8, 0xDEAD), (sp - 4, 0xBEEF), (sp, 0x11), (sp + 4, 0x22), (sp + 8, 0x33), (sp + 12, 0x44)]
    args = CallArguments(32, ParseRegisters(REGS_32), stack)
    assert args == [("[ESP]", 0x11), ("[ESP+0x4]", 0x22), ("[ESP+0x8]", 0x33), ("[ESP+0xc]", 0x44)]


def test_x86_ignores_words_below_the_stack_pointer():
    """Below ESP is dead space, not arguments - the pane shows it, this must not use it."""
    sp = 0x14FF28
    stack = [(sp - 8, 0xDEAD), (sp - 4, 0xBEEF), (sp, 0x11)]
    assert CallArguments(32, ParseRegisters(REGS_32), stack) == [("[ESP]", 0x11)]


def test_x86_is_capped():
    sp = 0x14FF28
    stack = [(sp + i * 4, i) for i in range(20)]
    assert len(CallArguments(32, ParseRegisters(REGS_32), stack)) == X86_ARG_COUNT


def test_x86_without_a_stack_pointer_yields_nothing():
    """Better nothing than arguments read from an arbitrary offset."""
    assert CallArguments(32, {"eax": 1}, [(0x1000, 1)]) == []


def test_x86_with_an_empty_stack_window():
    assert CallArguments(32, ParseRegisters(REGS_32), []) == []


# --- with a prototype supplying the argument count ---------------------------------
def test_x64_fifth_argument_onwards_comes_off_the_stack_above_the_shadow_space():
    """Only reachable because a prototype gave the count; CreateThread has six."""
    sp = 0x14FF28
    stack = [(sp + off, 0x1000 + off) for off in range(0, 0x60, 8)]
    args = CallArguments(64, ParseRegisters(REGS_64), stack, argCount=6)
    assert [name for name, _ in args] == ["RCX", "RDX", "R8", "R9", "[RSP+0x20]", "[RSP+0x28]"]
    assert args[4][1] == 0x1020
    assert args[5][1] == 0x1028


def test_x64_argument_count_below_four_truncates_the_registers():
    args = CallArguments(64, ParseRegisters(REGS_64), [], argCount=2)
    assert [name for name, _ in args] == ["RCX", "RDX"]


def test_x64_stack_arguments_need_the_stack_pointer():
    regs = {k: v for k, v in ParseRegisters(REGS_64).items() if k != "rsp"}
    args = CallArguments(64, regs, [(0x1000, 1)], argCount=6)
    assert [name for name, _ in args] == ["RCX", "RDX", "R8", "R9"]


def test_x86_argument_count_overrides_the_default_cap():
    sp = 0x14FF28
    stack = [(sp + i * 4, i) for i in range(20)]
    assert len(CallArguments(32, ParseRegisters(REGS_32), stack, argCount=7)) == 7
    assert len(CallArguments(32, ParseRegisters(REGS_32), stack, argCount=1)) == 1


def test_a_void_prototype_shows_no_arguments():
    assert CallArguments(64, ParseRegisters(REGS_64), [], argCount=0) == []
    assert CallArguments(32, ParseRegisters(REGS_32), [(0x14FF28, 1)], argCount=0) == []
