rule OysterBedConfig
{
    meta:
        author = "enzok"
        description = "OysterBed Config Extraction"
        cape_options = "bp0=$rc4decode_1+7,bp0=$rc4decode_2+7,hc0=1,count=0,action0=string:r8,typestring=Oyster Config"
        hash = "ecbe7875c593b2a78df82a16de05d59d06394c427b87bfb0d78a30035fad6409"
    strings:
        $endico = {80 [1-2] 65 75 ?? 80 [1-2] 01 6E 75 ?? 80 [1-2] 02 64 75 ?? 80 [1-2] 03 69 75 ?? 80 [1-2] 04 63 75 ?? 80 [1-2] 05 6F}
        $rc4decode_1 = {4? 8D 05 [4] 8B D7 4? 8B CD 4? 8B D8 E8 [4] 80 ?? 4D 74 ?? 80 ?? 01 5A}
        $rc4decode_2 = {4? 8D 05 [4] 4? 89 ?? E8 [4] 80 ?? 4D 74 ?? 80 ?? 01 5A 0F}
    condition:
        $endico and 1 of ($rc4decode_*)
}
