rule MirrorBlast_Loader32_Payload
{
    meta:
        author = "enzok"
        description = "MirrorBlast Loader Payload"
        cape_options = "bp0=$decrypted_buf+25,action0=dumpsize:eax,bp1=$decrypted_buf+30,action1=dump:eax,typestring1=MirrorBlastLoader Payload,count=0"

    strings:
        $decryptor = {8B 45 ?? 03 45 ?? 0F BE 08 0F B6 55 ?? 33 CA 8B 45 ?? 03 45 ?? 0F B6 10 33 CA 8B 45 ?? 03 45 ?? 88 08 8B 4D ?? 83 E9 01 39 4D ?? 75}
        $decrypted_buf = {E8 ?? ?? ?? FF 83 C4 ?? B? 4D 5A 00 00 8B 4D ?? 66 89 01 8B 55 ?? 8B 45 ?? 89 02}
    condition:
        any of them
}

rule MirrorBlast_Loader64_Payload
{
    meta:
        author = "enzok"
        description = "MirrorBlast Loader Payload"
        cape_options = "bp0=$decrypted_buf+27,action0=dumpsize:rcx,bp1=$decrypted_buf+34,action1=dump:rax,typestring1=MirrorBlastLoader Payload,count=0"

    strings:
        $decryptor_64 = {8B 04 24 4? 8B 4C 24 ?? 0F BE 04 01 0F B6 0C 24 33 C1 8B 4C 24 ?? 4? 8B 54 24 ?? 0F B6 0C 0A 33 C1 8B 0C 24 4? 8B 54 24 ?? 88 04 0A}
        $decrypted_buf = {E8 ?? ?? ?? FF B? 4D 5A 00 00 4? 8B 4C 24 ?? 66 89 01 4? 8B 44 24 ?? 8B 4C 24 ?? 89 08}
    condition:
        all of them
}