# Copyright (C) 2015 Kevin O'Reilly kevin.oreilly@contextis.co.uk
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

import logging
import re
from typing import Any, Dict

# CAPE output types. To correlate with cape\cape.h in monitor
COMPRESSION = 2
TYPE_STRING = 0x100

log = logging.getLogger(__name__)

code_mapping = {
    # UPX
    0x1000: "Unpacked PE Image",
    0x6A: "AMSI Buffer",
    0x6B: "AMSI Stream",
}

inject_map = {
    3: "Injected PE Image",
    4: "Injected Shellcode/Data",
}

unpack_map = {
    8: "Unpacked PE Image",
    9: "Unpacked Shellcode",
}

pe_map = {
    "PE32+": ": 64-bit ",
    "PE32": ": 32-bit ",
}

cape_name_regex = re.compile(r" (?:payload|config|loader|strings)$", re.I)


def get_cape_name_from_yara_hit(hit: Dict[str, Any]) -> str:
    """Use the cape_type as defined in the metadata for the yara hit
    (e.g. "SocGholish Payload") and return the part before
    "Loader", "Payload", "Config", or "Strings"
    """
    return get_cape_name_from_cape_type(hit["meta"].get("cape_type", ""))


def get_cape_name_from_cape_type(cape_type: str) -> str:
    """Return the part of the cape_type (e.g. "SocGholish Payload") preceding
    " Payload", " Config", " Loader", or " Strings"
    """
    if bool(cape_name_regex.search(cape_type)):
        return cape_name_regex.sub("", cape_type)
    else:
        return ""


def cape_type_string(type_strings, file_info, append_file):
    if file_info["cape_type_code"] in code_mapping:
        file_info["cape_type"] = code_mapping[file_info["cape_type_code"]]
        append_file = True
    if any(i in type_strings for i in ("PE32+", "PE32")):
        if not file_info["cape_type"]:
            return append_file
        pe_type = "PE32+" if "PE32+" in type_strings else "PE32"
        file_info["cape_type"] += pe_map[pe_type]
        file_info["cape_type"] += (
            "DLL" if type_strings[2] == ("(DLL)") else "executable"
        )
    elif type_strings[0] == "MS-DOS":
        file_info["cape_type"] = "DOS MZ image: executable"
    else:
        file_info["cape_type"] = file_info["cape_type"] or "PE image"
    return append_file


def metadata_processing(metadata):
    file_info = {}
    file_info["cape_type_code"] = 0
    file_info["cape_type"] = ""

    metastrings = metadata.split(";?")
    if len(metastrings) > 2:
        file_info["process_path"] = metastrings[1]
        file_info["process_name"] = metastrings[1].rsplit("\\", 1)[-1]
    if len(metastrings) > 3:
        file_info["module_path"] = metastrings[2]

    if "pids" in metadata:
        file_info["pid"] = (
            metadata["pids"][0]
            if len(metadata["pids"]) == 1
            else ",".join(metadata["pids"])
        )

    if metastrings and metastrings[0] and metastrings[0].isdigit():
        file_info["cape_type_code"] = int(metastrings[0])
        if file_info["cape_type_code"] == TYPE_STRING:
            if len(metastrings) > 4:
                file_info["cape_type_string"] = metastrings[3]

        elif file_info["cape_type_code"] == COMPRESSION:
            file_info["cape_type"] = "Decompressed PE Image"

        elif file_info["cape_type_code"] in inject_map:
            file_info["cape_type"] = inject_map[file_info["cape_type_code"]]
            if len(metastrings) > 4:
                file_info["target_path"] = metastrings[3]
                file_info["target_process"] = metastrings[3].rsplit("\\", 1)[-1]
                file_info["target_pid"] = metastrings[4]

        elif file_info["cape_type_code"] in unpack_map:
            file_info["cape_type"] = unpack_map[file_info["cape_type_code"]]
            if len(metastrings) > 4:
                file_info["virtual_address"] = metastrings[3]

    return file_info
