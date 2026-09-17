"""User-assigned names for addresses in the interactive debugger.

Names are stored against a module and an offset into it, not an absolute address: the same
sample loaded again may not land at the same base, and a name recorded absolutely would then
point at whatever happens to be there. Resolving offset to address needs the module list,
which arrives per break, so the stored form is the durable one and the absolute map is
derived from it.

The file is plain text, one name per line, so it can be read and edited by hand:

    # CAPEsolo debugger symbol names
    sample.exe+0x1374   DecryptConfig
    ntdll.dll+0x9a210   suspicious_stub

Pure functions plus two file operations, free of wx imports (see tests/test_symbol_names.py).
"""


import logging
import re
from pathlib import Path

log = logging.getLogger(__name__)

NAMES_FILENAME = "symbol_names.txt"
HEADER = "# CAPEsolo debugger symbol names. One per line: <module>+<hex offset> <name>\n"
# Deliberately no whitespace: the file format is whitespace-separated, and a name with a
# space in it could not be read back. The rest is what a symbol is usually allowed to be.
NAME_RX = re.compile(r"^[A-Za-z_][A-Za-z0-9_.@$]{0,63}$")
LINE_RX = re.compile(r"^(?P<mod>[^\s+]+)\+(?P<off>0[xX][0-9A-Fa-f]+|[0-9A-Fa-f]+)\s+(?P<name>\S+)$")


def IsValidName(name: str) -> bool:
    """Whether `name` can be stored and read back unambiguously."""
    return bool(NAME_RX.match(name or ""))


def ModuleOffset(addr: int, moduleRanges) -> tuple[str, int] | None:
    """(module, offset) for `addr`, or None if it is not inside a known module.

    `moduleRanges` is ConsolePanel's sorted list of (start, end, name). An address outside
    every module - freshly allocated shellcode, say - cannot be named durably, because there
    is nothing to measure the offset against that will exist next time.
    """
    for start, end, modName in moduleRanges:
        if start <= addr < end:
            return modName, addr - start

    return None


def Absolute(modName: str, offset: int, moduleRanges) -> int | None:
    """The address `modName`+`offset` currently resolves to, or None if it is not loaded."""
    for start, end, name in moduleRanges:
        if name.lower() == modName.lower():
            addr = start + offset
            return addr if addr < end else None

    return None


def ParseNames(text: str) -> dict[tuple[str, int], str]:
    """Names keyed by (module, offset), skipping blank lines, comments and malformed ones."""
    names = {}
    for lineNo, raw in enumerate(text.splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue

        m = LINE_RX.match(line)
        if not m:
            log.warning("[SYMBOLS] %s line %d is not a name entry: %r", NAMES_FILENAME, lineNo, raw)
            continue

        name = m.group("name")
        if not IsValidName(name):
            log.warning("[SYMBOLS] %s line %d has an unusable name: %r", NAMES_FILENAME, lineNo, name)
            continue

        names[(m.group("mod"), int(m.group("off"), 16))] = name

    return names


def FormatNames(names: dict[tuple[str, int], str]) -> str:
    """The file body for `names`, sorted so the file is stable between writes."""
    lines = [HEADER]
    for (modName, offset), name in sorted(names.items()):
        lines.append(f"{modName}+{offset:#x}\t{name}\n")

    return "".join(lines)


def NamesPath(analysisDir) -> Path | None:
    """Where names live for this analysis, or None if there is no analysis directory."""
    if not analysisDir:
        return None

    return Path(analysisDir) / "debugger" / NAMES_FILENAME


def ReadNamesFile(path) -> dict[tuple[str, int], str] | None:
    """Names from `path`, or None if it could not be read.

    None rather than an empty map because the two mean different things to a caller
    importing a file the user picked: unreadable is a failure to report, whereas a file with
    no usable lines in it is an answer. Nothing is logged for a missing file - the
    per-analysis load asks for one that does not exist yet on every first run.
    """
    try:
        return ParseNames(Path(path).read_text(encoding="utf-8"))
    except OSError:
        return None
    except UnicodeDecodeError:
        log.warning("[SYMBOLS] %s is not UTF-8; ignored", path)
        return None


def WriteNamesFile(path, names: dict[tuple[str, int], str]) -> bool:
    """Write `names` to `path`, creating its directory. False if it could not be written."""
    path = Path(path)
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(FormatNames(names), encoding="utf-8")
        return True
    except OSError as e:
        log.error("[SYMBOLS] Could not write %s: %s", path, e)
        return False


def LoadNames(analysisDir) -> dict[tuple[str, int], str]:
    """Read the per-analysis names, or an empty map if there are none yet."""
    path = NamesPath(analysisDir)
    if not path:
        return {}

    names = ReadNamesFile(path)
    return {} if names is None else names


def SaveNames(analysisDir, names: dict[tuple[str, int], str]) -> bool:
    """Write the names back, creating the debugger directory if needed."""
    path = NamesPath(analysisDir)
    if not path:
        return False

    return WriteNamesFile(path, names)
