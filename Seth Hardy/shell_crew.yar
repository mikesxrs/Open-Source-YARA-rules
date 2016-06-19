rule TROJAN_Notepad {
    meta:
        Author = "RSA_IR"
        Date     = "4Jun13"
        File     = "notepad.exe v 1.1"
        MD5      = "106E63DBDA3A76BEEB53A8BBD8F98927"
    strings:
        $s1 = "75BAA77C842BE168B0F66C42C7885997"
        $s2 = "B523F63566F407F3834BCC54AAA32524"
    condition:
        $s1 or $s2
}
rule Trojan_Derusbi {
    meta:
        Author = "RSA_IR"
        Date     = "4Sept13"
        File     = "derusbi_variants v 1.3"
        MD5      = " c0d4c5b669cc5b51862db37e972d31ec "

    strings:
        $b1 = {8b 15 ?? ?? ?? ?? 8b ce d3 ea 83 c6 ?? 30 90 ?? ?? ?? ?? 40 3b 05 ?? ?? ?? ?? 72 ??}
        $b2 = {F3 5D 88 2E ?? ?? 00 00 BE 07 18 2E F0 5D 88 2E F7 5D 88 2E 0C A2 88 2E 4B 5D 88 2E F3 5D 88 2E}
        $b3 = {4E E6 40 BB}
        $b4 = {B1 19 BF 44}
        $b5 = {6A F5 44 3D ?? ?? 00 00 27 AF D4 3D 69 F5 44 3D 6E F5 44 3D 95 0A 44 3D D2 F5 44 3D 6A F5 44 3D}
        $b6 = {F3 5D 88 2E ?? ?? 00 00 BE 07 18 2E F0 5D 88 2E}
        $b7 = {D6 D5 A4 A3 ?? ?? 00 00 9B 8F 34 A3 D5 D5 A4 A3 D2 D5 A4 A3 29 2A A4 A3}
        $b8 = {C3 76 33 9F ?? ?? 00 00 8E 2C A3 9F C0 76 33 9F C7 76 33 9F 3C 89 33 9F}

    condition:
        2 of ($b1, $b2, $b3, $b4) and 1 of ($b5, $b6, $b7, $b8)
}