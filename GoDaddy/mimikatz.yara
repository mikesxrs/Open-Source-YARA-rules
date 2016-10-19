
rule mimikatz_sekurlsa {
    strings:
        $s1 = { 33 DB 8B C3 48 83 C4 20 5B C3 }
        $s2 = {83 64 24 30 00 44 8B 4C 24 48 48 8B 0D}
        $s3 = {83 64 24 30 00 44 8B 4D D8 48 8B 0D}
        $s4 = {84 C0 74 44 6A 08 68}
        $s5 = {8B F0 3B F3 7C 2C 6A 02 6A 10 68}
        $s6 = {8B F0 85 F6 78 2A 6A 02 6A 10 68}

    condition:
        all of them
}

rule mimikatz_decryptkeysign {
    strings:
        $s1 = { F6 C2 07 0F 85 0D 1A 02 00 }
        $s2 = { F6 C2 07 0F 85 72 EA 01 00 }
        $s3 = { 4C 8B CB 48 89 44 24 30}
        $s4 = { 4c 89 1b 48 89 43 08 49 89 5b 08 48 8d }

    condition:
        3 of them
}

