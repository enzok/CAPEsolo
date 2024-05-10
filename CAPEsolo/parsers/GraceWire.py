from __future__ import absolute_import
import yara
from struct import unpack_from
import pefile

rule_source = """
rule GraceWire {
  meta:
    author = "enzok"
    description = "GraceWire Payload"
    cape_type = "GraceWire Payload"

  strings:
    $dat_password = { 68 ?? ?? ?? ?? 6A 10 68 ?? ?? ?? ?? 8B D8 E8 ?? ?? ?? ?? 83 C4 0C 68 ?? ?? ?? ?? 6A 10 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 C4 0C }
    $bin_password = { 68 ?? ?? ?? ?? 6A 10 68 ?? ?? ?? ?? A3 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 C4 0C 8D 4D C0 E8 ?? ?? ?? ?? } 
    $ip_address = /(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\.(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\.(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\.(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9]):\d{1,5}/ wide ascii
    $version_string = /i'm ready (\(configuration = .+, version = .+, api = \d+, build = \d+\))/ wide ascii

  condition:
    2 of them
}

"""


def fix_ips(hits):
    config_dict = {}

    i = -1
    config_dict["Initial C2"] = []
    for item in hits:
        prev_offset = hits[i][0] + 1
        if item.instances[0].offset == prev_offset:
            i += 1
            continue
        config_dict["Initial C2"].append(item.instances[0].matched_data)
        i += 1

    return config_dict


def get_password(filebuf, name, hits):
    config_dict = {}
    config_dict[name] = []

    pe = pefile.PE(data=filebuf, fast_load=False)
    image_base = pe.OPTIONAL_HEADER.ImageBase

    for item in hits:
        pwdva_offset = unpack_from("i", filebuf, item.instances[0].offset + 8)[0] - image_base
        pwd_offset = pe.get_offset_from_rva(pwdva_offset)
        password = unpack_from("16c", filebuf, pwd_offset)
        config_dict[name].append("".join(password))

    return config_dict


def yara_scan(raw_data, rule_name):
    hits = []
    try:
        yara_rules = yara.compile(source=rule_source)
        matches = yara_rules.match(data=raw_data)
        for match in matches:
            if match.rule == "GraceWire":
                for item in match.strings:
                    if rule_name:
                        if item.identifier == rule_name:
                            hits.append(item)
    except Exception as e:
        print(e)

    return hits


def config(task_info, data):
    hits = {}
    hits["dat_password"] = yara_scan(data, rule_name="$dat_password")
    hits["bin_password"] = yara_scan(data, rule_name="$bin_password")
    hits["ip_address"] = yara_scan(data, rule_name="$ip_address")
    hits["version_string"] = yara_scan(data, rule_name="$version_string")

    if not hits:
        return
    cfg_dict = {}
    if hits["version_string"]:
        cfg_dict["Version String"] = hits["version_string"][0].instances[0].matched_data[9:]

    cfg_dict.update(fix_ips(hits["ip_address"]))
    cfg_dict.update(get_password(data, "dat password", hits["dat_password"]))
    cfg_dict.update(get_password(data, "bin password", hits["bin_password"]))

    return cfg_dict
