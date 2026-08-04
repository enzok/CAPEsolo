rule BubbleLoader
{
    meta:
        author = "enzok"
        description = "BubbleLoader Loader"
        cape_type = "BubbleLoader Loader"
        hash1 = "5397e96e590d5274bdbdb353c651d0c7087c848c640f5199c62a00720050b9a4"
        hash2 = "aa86a08cf0f2bcdc26a04c4fba92957e0ecbc5d2c9f1e2c7278b6498a6738a41"
        hash3 = "a7fc44c3665cb254f73fc16e4950eb111f910573e0f0cf63471cce69c04fc684"
    strings:
        $res_stub = { 49 45 4e 44 ae 42 60 82 89 50 4e 47 0d 0a 1a 0a 00 00 00 0d 49 48 44 52 55 48 [2] 48 83 [2] 49 55 41 56 53 [4] 51 52 [2] 08 15 09 d7 94 dc a4 }
        $stub = { 55 48 [2] 48 83 [2] 49 55 41 56 53 [4] 51 52 [2] 08 15 09 d7 94 dc a4 }
        $loader = { 48 8d 0d [3] 00 31 d2 41 b8 60 00 00 00 ff 15 [3] 00 48 85 c0 0f 84 [3] 00 48 89 c7 4c 8d 05 [3] 00 ba 0a 00 00 00 48 89 c1 45 31 c9 ff 15 [3] 00 48 85 c0 }
    condition:
        uint16(0) == 0x5A4D and any of them
}
