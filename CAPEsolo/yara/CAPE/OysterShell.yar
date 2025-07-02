rule OysterShell
{
    meta:
        author = "enzok"
        description = "OysterShell Payload"
        cape_type = "OysterShell Payload"
        hash = ""
    strings:
        $endico = {80 [1-2] 65 75 ?? 80 [1-2] 01 6E 75 ?? 80 [1-2] 02 64 75 ?? 80 [1-2] 03 69 75 ?? 80 [1-2] 04 63 75 ?? 80 [1-2] 05 6F}
        $rc4decode_1 = {4? 8D 05 [4] E8 [4] 80 ?? 4D 74 ?? 80 ?? 01 5A 75}
        $up1 = "/secure/up" wide ascii
    condition:
        all of them
}
