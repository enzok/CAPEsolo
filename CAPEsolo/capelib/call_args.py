"""Outgoing call arguments for the interactive debugger's disassembly view.

Pure functions on plain dicts and tuples, free of wx and pipe imports so the calling
convention arithmetic can be exercised without a GUI (see tests/test_call_args.py).

Values only, with no parameter names. Naming them needs a positional prototype table, which
this project does not have: logtbl.py looks like one but lists only the arguments capemon
chose to log, at non-contiguous positions - NtAllocateVirtualMemory has six parameters and
four names there, skipping the third. Mapping argument N to the Nth name would confidently
mislabel registers, which is worse in a debugger than leaving them unlabelled.

Everything here is derived from state already fetched every break: the register pane's text
and the stack window. No extra pipe traffic.
"""


import re

# System V is not relevant: this debugs Windows targets only.
X64_ARG_REGISTERS = ("rcx", "rdx", "r8", "r9")
# Arguments shown for a 32-bit target, where every one is on the stack and the count is
# unknown without a prototype. Four covers the common Win32 call and stops the annotation
# running away; the stack pane is there for the rest.
X86_ARG_COUNT = 4
REG_RX = re.compile(r"\b([A-Za-z][A-Za-z0-9]{1,3})\s*:\s*([0-9A-Fa-f]+)\b")


def ParseRegisters(regsText: str) -> dict[str, int]:
    """Register name (lowercased) -> value, from the register pane's text.

    Flag fields match the same shape and land in here too, which is harmless: nothing looks
    up a flag by name, and excluding them would mean knowing every register set capemon
    prints.
    """
    return {m.group(1).lower(): int(m.group(2), 16) for m in REG_RX.finditer(regsText)}


def CallArguments(bits: int, regVals: dict[str, int], stackWords) -> list[tuple[str, int]]:
    """The arguments a call at the current instruction is about to pass.

    `stackWords` is (address, value) in ascending address order, as the stack pane holds it.

    Only valid with CIP on the call, before it executes. One instruction later the return
    address has been pushed and every 32-bit argument has moved by a word, so the caller has
    to check that rather than assume it.

    32-bit Windows passes everything on the stack whatever the convention - stdcall, cdecl and
    thiscall differ in who cleans up and whether ecx is used, not in where the stack arguments
    sit - so the first words at the stack pointer are the arguments either way.
    """
    if bits == 64:
        return [
            (reg.upper(), regVals[reg])
            for reg in X64_ARG_REGISTERS
            if reg in regVals
        ]

    sp = regVals.get("esp")
    if sp is None:
        return []

    args = []
    for address, value in stackWords:
        if address < sp:
            continue

        args.append((f"[ESP+{address - sp:#x}]" if address > sp else "[ESP]", value))
        if len(args) == X86_ARG_COUNT:
            break

    return args


# Values a VirtualQuery/VirtualProtect protection argument can take, so a call argument that
# is one can be named instead of shown as a bare number. Only exact matches: an arbitrary
# integer that happens to share bits is not a protection constant.
PROTECT_VALUES = frozenset(
    base | modifier
    for base in (0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80)
    for modifier in (0x00, 0x100, 0x200, 0x400)
)
