# Copyright (C) 2010-2015 Cuckoo Foundation, Optiv, Inc. (brad.spengler@optiv.com)
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import logging
import re
from pathlib import Path

from CAPEsolo.capelib.utils import bytes2str

log = logging.getLogger(__name__)


def extract_strings(
    filepath: str = False,
    nulltermonly: bool = False,
    data: bytes = False,
    dedup: bool = False,
    minchars: int = 0,
):
    """Extract strings from analyzed file.
    @return: list of printable strings.
    """
    if filepath:
        p = Path(filepath)
        if not p.exists():
            log.error("Sample file doesn't exist: %s", filepath)
            return
        try:
            data = p.read_bytes()
        except (IOError, OSError) as e:
            log.error("Error reading file: %s", e)
            return

    if not data:
        return

    endlimit = b"8192"
    if nulltermonly:
        apat = b"([\x20-\x7e]{" + str(minchars).encode() + b"," + endlimit + b"})\x00"
        upat = (
            b"((?:[\x20-\x7e][\x00]){"
            + str(minchars).encode()
            + b","
            + endlimit
            + b"})\x00\x00"
        )
    else:
        apat = b"[\x20-\x7e]{" + str(minchars).encode() + b"," + endlimit + b"}"
        upat = (
            b"(?:[\x20-\x7e][\x00]){" + str(minchars).encode() + b"," + endlimit + b"}"
        )

    strings = [bytes2str(string) for string in re.findall(apat, data)]
    strings.extend(str(ws.decode("utf-16le")) for ws in re.findall(upat, data))

    if dedup:
        strings = list(set(strings))

    return strings
