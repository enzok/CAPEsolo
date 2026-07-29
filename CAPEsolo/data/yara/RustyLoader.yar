rule RustyLoader
{
    meta:
        author = "enzok"
        description = "RustyLoader Unpacker"
        cape_options = "clear,bp0=$mz_check*-4,action0=dumpimage:&src,count=0"
        hash = "93389f4234f81358fa29c65473b5bfc3c60ab7b3c2189185988f03a66aeda66f"
    strings:
        $seed = {0F 11 [3] 00 00 48 B8 [8] 48 89 85 [4] C7 85 [8] 66 C7 85}
        $mz_check = {4? 63 ?? 3C 31 C0 4? 85 ?? 0F 95 C0 66 81 3? 4D 5A}
    condition:
        uint16(0) == 0x5A4D and all of them
}