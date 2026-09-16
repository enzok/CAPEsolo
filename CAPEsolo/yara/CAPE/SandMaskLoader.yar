rule SandMask_Loader_Embedded
{
    meta:
        description = "SandMask Loader Embedded Payload"
        cape_type = "SandMaskLoader Loader"

    strings:
        $key = { 48 83 EC ?? C7 05 [8] E8 [4] 84 C0 74 }
        $block_1 = { 48 89 5C 24 ?? BB 3C 00 00 00 }
        $block_2 = { B9 10 27 00 00 FF 15 [3] 00 48 83 EB 01 75 }
        $block_3 = { 48 8B 5C 24 ?? 32 C0 48 83 C4 ?? C3 }
        $block_4 = { B9 10 27 00 00 FF 15 [3] 00 32 C0 48 83 C4 ?? C3 }
        $payload = { C7 05 [8] 48 8D 05 [4] C3}

    condition:
        $key and $payload and 3 of ($block*)
}

rule SandMask_Loader_File
{
    meta:
        description = "SandMask Loader File Payload"
        cape_type = "SandMaskLoader Loader"

    strings:
        $key = { 48 83 EC ?? C7 05 [8] E8 [4] 84 C0 74 }
        $block_1 = { 48 89 5C 24 ?? BB 3C 00 00 00 }
        $block_2 = { B9 10 27 00 00 FF 15 [3] 00 48 83 EB 01 75 }
        $block_3 = { 48 8B 5C 24 ?? 32 C0 48 83 C4 ?? C3 }
        $block_4 = { B9 10 27 00 00 FF 15 [3] 00 32 C0 48 83 C4 ?? C3 }
        $payload = { 48 8D 0D [4] E8 [4] 48 89 05 [3] 00 48 85 C0 74 ?? 81 05 [3] 00 FF 00 00 00 48 83 C4 ?? C3 }
        $file_read = { 48 [4] 45 33 C9 48 [4] 00 00 00 00 C7 [3] 80 00 00 00 BA 00 00 00 80 C7 [3] 03 00 00 00 }

    condition:
        $key and $payload and 3 of ($block*) and $file_read
}

rule SandMask_Loader_Download
{
    meta:
        description = "SandMask Loader Download Payload"
        cape_type = "SandMaskLoader Loader"

    strings:
        $key = { 48 83 EC ?? C7 05 [8] E8 [4] 84 C0 74 }
        $block_1 = { 48 89 5C 24 ?? BB 3C 00 00 00 }
        $block_2 = { B9 10 27 00 00 FF 15 [3] 00 48 83 EB 01 75 }
        $block_3 = { 48 8B 5C 24 ?? 32 C0 48 83 C4 ?? C3 }
        $block_4 = { B9 10 27 00 00 FF 15 [3] 00 32 C0 48 83 C4 ?? C3 }
        $payload = { 48 8D 0D [4] E8 [4] 48 89 05 [3] 00 48 85 C0 74 ?? 81 05 [3] 00 FF 00 00 00 48 83 C4 ?? C3 }
        $ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/127.0.0.0 Safari/537.36" ascii
    condition:
        $key and $payload and 3 of ($block*) and $ua
}