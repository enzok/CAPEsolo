"""API prototypes for naming call arguments in the interactive debugger.

Declarations are stored and entered in the form the documentation gives them, so a prototype
can be pasted straight from a docs page without being rewritten:

    BOOL GetSystemTimes(
      [out, optional] PFILETIME lpIdleTime,
      [out, optional] PFILETIME lpKernelTime,
      [out, optional] PFILETIME lpUserTime
    );

One parser serves both the packaged table and whatever the analyst adds at runtime, which is
the reason for choosing that format over something easier to parse: the alternative is asking
the user to transcribe into a bespoke syntax, and a transcription error produces a
mislabelled register rather than a parse failure.

Pure functions plus two file reads, free of wx imports (see tests/test_api_protos.py).
"""


import logging
import os
import re
from collections import namedtuple
from pathlib import Path

log = logging.getLogger(__name__)

PROTOTYPES_FILENAME = "api_prototypes.h"
PROTOTYPES_ENV = "CAPESOLO_PROTOTYPES"
DEFAULT_PUBLIC_DIR = r"C:\Users\Public"

Param = namedtuple("Param", ["type", "name", "direction"])
Prototype = namedtuple("Prototype", ["name", "returnType", "params"])

# Calling conventions and export decorations, which carry no information here.
NOISE_WORDS = frozenset(
    (
        "winapi", "apientry", "__stdcall", "__cdecl", "__fastcall", "stdcall", "cdecl",
        "callback", "winbaseapi", "wincrypt32api", "ntapi", "ntsysapi", "extern", "const",
        "struct", "union", "enum", "unsigned", "signed", "far", "near", "_far", "_near",
    )
)
COMMENT_RX = re.compile(r"/\*.*?\*/|//[^\n]*", re.DOTALL)
# Bracketed SAL, as the docs write it: [in], [out, optional], [in, out].
BRACKET_SAL_RX = re.compile(r"\[[^\]]*\]")
# Underscore SAL, as headers write it: _In_, _Out_opt_, _In_reads_bytes_(cb), _Reserved_.
UNDERSCORE_SAL_RX = re.compile(r"\b_[A-Za-z][A-Za-z0-9_]*_(?:\s*\([^)]*\))?", re.IGNORECASE)
IDENTIFIER_RX = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
# `RET NAME ( params ) ;` - the name is the last identifier before the parameter list.
# The parameter group is greedy so it ends at the *last* close paren rather than the first:
# a SAL annotation carries its own parentheses, and `_In_reads_bytes_(nSize)` used to end the
# parameter list there and silently drop every parameter after it. Bounded by `[^;]` so it
# cannot run past the end of one declaration into the next.
DECL_RX = re.compile(r"(?P<head>[^;()]*?)\b(?P<name>[A-Za-z_][A-Za-z0-9_@]*)\s*\((?P<params>[^;]*)\)\s*;?", re.DOTALL)


def _Direction(annotation: str) -> str:
    """"in", "out", "inout" or "" from whatever SAL the declaration used."""
    text = annotation.lower()
    hasIn = "in" in re.findall(r"[a-z]+", text) or "_in_" in text or text.startswith("_in")
    hasOut = "out" in re.findall(r"[a-z]+", text) or "_out_" in text or "out" in text
    if "inout" in text.replace(",", "").replace(" ", "") or (hasIn and hasOut):
        return "inout"
    if hasOut:
        return "out"
    if hasIn:
        return "in"

    return ""


def ParseParam(text: str) -> Param | None:
    """One parameter declaration, SAL and pointer decoration removed.

    Returns None for `void`, which is how a no-argument function is written, and for anything
    with no identifier left to use as a name.
    """
    annotation = " ".join(BRACKET_SAL_RX.findall(text) + UNDERSCORE_SAL_RX.findall(text))
    body = UNDERSCORE_SAL_RX.sub(" ", BRACKET_SAL_RX.sub(" ", text))
    # An array suffix belongs to the type, and the name is what is wanted.
    body = re.sub(r"\[[^\]]*\]", " ", body)
    # Whether this is a pointer has to be settled before the stars go, or `void *` - a real
    # parameter - is indistinguishable from the bare `void` that means there are none.
    isPointer = "*" in body
    words = [w for w in body.replace("*", " ").split() if w.lower() not in NOISE_WORDS]
    if not words or (not isPointer and words[-1].lower() == "void"):
        return None

    if len(words) == 1:
        # A type with no parameter name, as the docs sometimes give for a single argument.
        return Param(words[0], words[0], _Direction(annotation))

    return Param(" ".join(words[:-1]), words[-1], _Direction(annotation))


def SplitParams(text: str) -> list[str]:
    """Split a parameter list on commas that are not inside brackets or parentheses."""
    parts, depth, current = [], 0, []
    for ch in text:
        if ch in "([":
            depth += 1
        elif ch in ")]":
            depth -= 1

        if ch == "," and depth == 0:
            parts.append("".join(current))
            current = []
        else:
            current.append(ch)

    parts.append("".join(current))
    return [p for p in (part.strip() for part in parts) if p]


def ParsePrototype(text: str) -> Prototype | None:
    """A single declaration, or None if it does not look like one."""
    text = COMMENT_RX.sub(" ", text).strip()
    if not text:
        return None

    m = DECL_RX.search(text)
    if not m:
        return None

    name = m.group("name")
    head = UNDERSCORE_SAL_RX.sub(" ", m.group("head")).replace("*", " ")
    returnType = " ".join(w for w in head.split() if w.lower() not in NOISE_WORDS) or "void"
    params = [p for p in (ParseParam(part) for part in SplitParams(m.group("params"))) if p]
    return Prototype(name, returnType, params)


def ParsePrototypes(text: str) -> dict[str, Prototype]:
    """Every declaration in `text`, keyed by function name.

    Declarations are separated by semicolons, so a file is just a run of them and a pasted
    block with a trailing semicolon parses the same as one without.
    """
    found = {}
    for chunk in COMMENT_RX.sub(" ", text).split(";"):
        proto = ParsePrototype(chunk)
        if proto:
            found[proto.name] = proto

    return found


def packaged_prototypes_path() -> Path:
    """The table shipped inside the package. Overwritten by pip upgrades."""
    return Path(__file__).resolve().parent.parent / "data" / PROTOTYPES_FILENAME


def user_prototypes_path() -> Path:
    """Where prototypes added at runtime go, which pip never touches.

    Beside the user cfg.ini, for the same reason: config and additions live next to the
    analysis data rather than inside a package directory an upgrade replaces.
    """
    override = os.environ.get(PROTOTYPES_ENV, "").strip()
    if override:
        return Path(override)

    public = os.environ.get("PUBLIC", "").strip() or DEFAULT_PUBLIC_DIR
    return Path(public) / "CAPEsolo" / PROTOTYPES_FILENAME


def LoadPrototypes() -> dict[str, Prototype]:
    """Packaged table then user additions, so an addition overrides a packaged declaration."""
    protos: dict[str, Prototype] = {}
    for path in (packaged_prototypes_path(), user_prototypes_path()):
        try:
            text = path.read_text(encoding="utf-8")
        except OSError:
            continue
        except UnicodeDecodeError:
            log.warning("[PROTOTYPES] %s is not UTF-8; skipped", path)
            continue

        protos.update(ParsePrototypes(text))

    return protos


def AppendUserPrototype(text: str) -> None:
    """Add a declaration to the user file, creating it if this is the first one."""
    path = user_prototypes_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as handle:
        handle.write(f"\n{text.strip().rstrip(';')};\n")
