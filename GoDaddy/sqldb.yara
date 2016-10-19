
rule ismserver {
    strings:
        // 578C1DBBCA1EA1F80D7101564D83D18D @ 0x401bf0
        $stringset = { 558BEC81EC80040000A1????????33C58945FC8B450853566A008BF18B96A80000006A048D8D8CFBFFFF5152898580FBFFFFC78584FBFFFF03000000C78588FBFFFF00000000B302C7858CFBFFFF05020002FF15????????68580200008D85A4FDFFFF6A0050E8???????? }

    condition:
        IsPeFile and $stringset
}

rule infov {
    strings:
        // AB8D3A4368861FE3E162AEF00B2D0112 @ 0x4028e0
        $connect_to_host = { 5355568BF1578B3D????????8D5E488D6E04538BCDE8????????85C075178B86EC0000008D04808D04808D0480C1E00350FFD7EBDD5F5E5D5BC3 }
        $successed = "Install service Successed\n"

    condition:
        IsPeFile and ($connect_to_host or $successed)
}

