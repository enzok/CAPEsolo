rule Nitrogen
{
    meta:
        author = "enzok"
        description = "Nitrogen Loader"
        cape_type = "NitrogenLoader Config"
    strings:
		$iv = {8B 84 24 [4] 8B 4C 24 ?? 0F AF C8 8B C1 [0-20] 89 44 24 ?? 48 8D 15 [3] 00}
		$aeskey = {48 8D 8C 24 [4] E8 [3] 00 48 8B C8 E8 [3] 00 4? 89 84 24 [4] 4? 8D 15 [3] 00}
		$decrypt1 = {48 89 54 24 ?? 4? 89 4C 24 ?? 4? 83 EC ?? C6 44 24 ?? 00 4? 8B 44 24 ?? 4? 8B 54 24 ?? B? 0E E8 [3] FF C6 44 24 ?? 0D}
		$decrypt2 = {EB ?? 0F B6 44 24 ?? FE C8 88 44 24 ?? 4? 8B 4C 24 ?? E8 [3] FF 4? 8B 4C 24 ?? E8 [3] FF 4? 8B 44 24 ?? 4? 8B 54 24 ?? 0F}
		$decrypt3 = {B6 4C 24 ?? E8 [3] FF 0F B6 44 24 ?? 85 C0 75 ?? EB ?? 4? 8B 4C 24 ?? E8 [3] FF EB ?? 33 C0 4? 83 C4 ?? C3}
    condition:
        $iv and $aeskey and 2 of ($decrypt*)
}
