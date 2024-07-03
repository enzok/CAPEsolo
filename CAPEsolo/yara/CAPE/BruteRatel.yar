rule BruteRatel
{
    meta:
        author = "kevoreilly"
        description = "BruteRatel Config"
        cape_type = "BruteRatel Payload"
    strings:
        $config = {41 57 41 56 41 55 41 54 55 57 56 53 48 81 EC 28 01 00 00 48 83 B9 28 03 01 00 00}
        $decode = {55 57 56 53 48 83 EC ?? 31 C0 48 89 CB 48 89 D7 44 89 C6 44 89 CD 44 39 01 77 ?? 41 8D 48 01 E8 [4] 31 C9}
    condition:
        all of them
}