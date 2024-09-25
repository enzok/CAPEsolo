rule NitrogenLoaderSyscall
{
    meta:
        author = "enzok"
        description = "NitrogenLoader Syscall Bypass"
        cape_options = "sysbp=$syscall*-2,count=0"

    strings:
        $makehashes = {48 89 4C 24 ?? 48 89 54 24 ?? 4? 89 44 24 ?? 4? 89 4C 24 ?? 4? 83 EC ?? B? [4] E8 [3] 00}
        $number = {49 89 C3 B? [4] E8 [3] 00}
        $syscall = {48 83 C4 ?? 4? 8B 4C 24 ?? 4? 8B 54 24 ?? 4? 8B 44 24 ?? 4? 8B 4C 24 ?? 4? 89 CA 4? FF E3}

    condition:
        all of them
}

rule NitrogenLoaderAES
{
    meta:
        author = "enzok"
        description = "NitrogenLoader AES and IV"
        cape_options = "bp0=$keyiv0+8,action0=dump:ecx::64,hc0=1,bp1=$keyiv0*-4,action1=dump:ecx::32,hc1=1,count=0"

    strings:
        $keyiv0 = {48 8B 8C 24 [4] E8 [3] 00 4? 89 84 24 [4] 4? 8B 84 24 [4] 4? 89 84 24 [4] 4? 8B 8C 24 [4] E8 [3] 00}
		$keyiv1 = {48 89 84 24 [4] 4? 8B 84 24 [4] 4? 8B 94 24 [4] 4? 8D 8C 24 [4] E8 [3] FF}
		$keyiv2 = {48 63 84 24 [4] 4? 8B C0 4? 8B 94 24 [4] 4? 8D 8C 24 [4] E8 [3] FF 4? 8B 84 24}

    condition:
        all of them
}
