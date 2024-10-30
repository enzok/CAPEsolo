rule Memexec
{
    meta:
        author = "enzok"
        description = "Memexec Loader"
        cape_options = "bp0=$anti_analysis*-5,action0=jmp:11,bp1=$mz_header_check,action1=dump:rcx::rdx,count=1"
    strings:
        $anti_analysis = {48 0F AF C1 4? 83 CA 01 4? 21 C2 4? 01 C2 74 ?? 4? 8B 4D ?? 4? B? 01 00 00 00 E8 [3] 00 84 DB 0F 84 [3] 00}
        $mz_header_check = {44 0F B7 01 4? 63 41 3C 4? 31 C9 4? 85 C0 4? 0F 95 C1 4? 31 D2 4? 81 F8 4D 5A 00 00}
        $pe_header_check = {44 0F B7 44 08 18 4? 81 F8 0B 02 00 00 74 ?? 4? B? 05 4? 81 F8 0B 01 00 00 75 ?? 4? B? 02 81 3C 01 50 45 00 00}
    condition:
        3 of them
}
