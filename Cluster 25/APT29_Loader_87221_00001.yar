import "pe"
rule APT29_Loader_87221_00001 {
    meta:
        author = "Cluster25"
        tlp = "white"
        description = "Detects DLL loader variants used in Nobelium kill-chain"
        hash1 = "6fc54151607a82d5f4fae661ef0b7b0767d325f5935ed6139f8932bc27309202"
        hash2 = "23a09b74498aea166470ea2b569d42fd661c440f3f3014636879bd012600ed68"
        report = "https://blog.cluster25.duskrise.com/2022/05/13/cozy-smuggled-into-the-box"
    strings:
        $s1 = "%s\\blank.pdf" fullword ascii
        $s2 = "%s\\AcroSup" fullword ascii
        $s3 = "vcruntime140.dll" fullword ascii
        $s4 = "ME3.99.5UUUUUUUUUUU" fullword ascii
        $c1 = "Rock" fullword ascii
        $c2 = ".mp3" fullword ascii
        $c3 = "%s.backup" fullword ascii
        $sequence1 = { C7 45 ?? 0B 00 10 00 48 8B CF FF 15 ?? ?? ?? 00 85 C0 74 ?? 48 8D 55 ?? 48 89 75 ?? 48 8B CF FF 15 ?? ?? ?? 00 85 C0 74 ?? 48 8B CF FF 15 ?? ?? ?? 00 } // Thread contect change
        $sequence2 = { 0F B6 0B 4C 8D 05 ?? ?? ?? 00 89 4C 24 ?? 4D 8B CD 49 8B CD BA 04 01 00 00 E8 ?? ?? ?? ?? 48 8D 5B 01 48 83 EF 01 75 ?? } // encoding cycle
        $sequence3 = { 4C 8D 8C 24 ?? 00 00 00 8B 53 ?? 44 8D 40 ?? 48 03 CD 44 89 A4 24 ?? 00 00 00 FF 15 ?? ?? ?? 00 8B 43 ?? 44 8B 43 ?? 4A 8D 14 38 48 8D 0C 28 E8 ?? ?? 00 00 8B 4B ?? 4C 8D 8C 24 ?? 00 00 00 8B 53 ?? 48 03 CD 44 8B 84 24 ?? 00 00 00 FF 15 ?? ?? ?? 00 } //DLL Unhook
        $sequence4 = { 42 0F B6 8C 32 ?? ?? ?? 00 48 83 C2 03 88 0F 48 8D 7F 01 48 83 FA 2D 7C E7 } // get domain name string
    condition:
        uint16(0) == 0x5a4d and filesize < 200KB
            and pe.imports("kernel32.dll", "SetThreadContext") and pe.imports("kernel32.dll", "ResumeThread") and pe.imports("kernel32.dll", "K32GetModuleFileNameExA")
            and 3 of ($s*)
            and all of ($c*)
            and 3 of ($sequence*)
}