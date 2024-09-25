DESCRIPTION = "Nitrogen loader parser"
AUTHOR = "enzok"

import logging
from contextlib import suppress
from hashlib import sha256

import pefile
import yara
from Cryptodome.Cipher import AES
from Cryptodome.Util.Padding import unpad

log = logging.getLogger(__name__)

rule_source = """
rule NitrogenLoader
{
    meta:
        author = "enzok"
        description = "Nitrogen Loader"
        cape_type = "NitrogenLoader Loader"
    strings:
		$iv = {8B 84 24 [4] 8B 4C 24 ?? 0F AF C8 8B C1 [0-20] 89 44 24 ?? 48 8D 15 [3] 00}
		$aeskey = {48 8D 8C 24 [4] E8 [3] 00 48 8B C8 E8 [3] 00 4? 89 84 24 [4] 4? 8D 15 [3] 00}
		$decrypt1 = {48 89 54 24 ?? 4? 89 4C 24 ?? 4? 83 EC ?? C6 44 24 ?? 00 4? 8B 44 24 ?? 4? 8B 54 24 ?? B? 0E E8 [3] FF C6 44 24 ?? 0D}
		$decrypt2 = {EB ?? 0F B6 44 24 ?? FE C8 88 44 24 ?? 4? 8B 4C 24 ?? E8 [3] FF 4? 8B 4C 24 ?? E8 [3] FF 4? 8B 44 24 ?? 4? 8B 54 24 ?? 0F}
		$decrypt3 = {B6 4C 24 ?? E8 [3] FF 0F B6 44 24 ?? 85 C0 75 ?? EB ?? 4? 8B 4C 24 ?? E8 [3] FF EB ?? 33 C0 4? 83 C4 ?? C3}
    condition:
        $iv and $aeskey and 2 of ($decrypt*)
}
"""

yara_rules = yara.compile(source=rule_source)


def decrypt_aes_cbc(encrypted_data, key, iv):
    decoded = ""
    with (suppress(Exception)):
        cipher = AES.new(key, AES.MODE_CBC, iv)
        decrypted_data = cipher.decrypt(encrypted_data)
        decoded = unpad(decrypted_data, AES.block_size)

    return decoded


def extract_config(filebuf):
    config = {}
    try:
        pe = pefile.PE(data=filebuf, fast_load=False)
    except pefile.PEFormatError:
        return
    matches = yara_rules.match(data=filebuf)
    if not matches:
        return

    iv = ""
    aeskey = ""
    iv_offset = ""
    aes_key_offset = ""
    for match in matches:
        if match.rule != "NitrogenLoader":
            continue
        for item in match.strings:
            if "$iv" in item.identifier:
                iv_match_offset = item.instances[0].offset
                iv_offset = item.instances[0].matched_data[-4:]
                iv_len = len(item.instances[0].matched_data)

            if "$aeskey" == item.identifier:
                aes_key_match_offset = item.instances[0].offset
                aes_key_offset = item.instances[0].matched_data[-4:]
                aes_key_len = len(item.instances[0].matched_data)

    if iv_offset and aes_key_offset:
        iv_delta = int.from_bytes(iv_offset, byteorder="little")
        offset = pe.get_offset_from_rva(iv_delta + pe.get_rva_from_offset(iv_match_offset) + iv_len)
        iv = filebuf[offset : offset + 32]
        config["IV"] =  iv.decode("utf-8")
        aes_key_delta = int.from_bytes(aes_key_offset, byteorder="little")
        offset = pe.get_offset_from_rva(aes_key_delta + pe.get_rva_from_offset(aes_key_match_offset) + aes_key_len)
        aeskey = filebuf[offset : offset + 64]
        config["AES key"] = aeskey.decode("utf-8")

    if iv and aeskey and hasattr(pe, "DIRECTORY_ENTRY_RESOURCE"):
        iv = bytes.fromhex(iv.decode())
        aeskey = bytes.fromhex(aeskey.decode())
        for rsrc in pe.DIRECTORY_ENTRY_RESOURCE.entries:
            for entry in rsrc.directory.entries:
                offset = entry.directory.entries[0].data.struct.OffsetToData
                size = entry.directory.entries[0].data.struct.Size
                res_data = pe.get_memory_mapped_image()[offset: offset + size]
                if len(res_data) < 32:
                    continue

                if res_data[:2] == b"MZ":
                    config["Decoy sha256"] = sha256(res_data).hexdigest()
                elif size <= 256:
                    decrypted_res = decrypt_aes_cbc(res_data, aeskey, iv)
                    config["Decoy file name"] = decrypted_res.decode("utf-8")
                else:
                    with suppress(Exception):
                        decrypted_res = decrypt_aes_cbc(res_data, aeskey, iv)
                        config["Payload sha256"] = sha256(decrypted_res).hexdigest()

    return config


if __name__ == "__main__":
    import sys
    from pathlib import Path

    filepath = sys.argv[1]
    log.setLevel(logging.DEBUG)
    data = Path(filepath).read_bytes()
    print(extract_config(data))
