rule Windows_Trojan_BLISTER {
    meta:
        Author = "Elastic Security"
        creation_date = "2022-04-29"
        last_modified = "2022-04-29"
        os = "Windows"
        arch = "x86"
        category_type = "Trojan"
        family = "BLISTER"
        threat_name = "Windows.Trojan.BLISTER"
        description = "Detects BLISTER loader."
        reference = "https://www.elastic.co/security-labs/elastic-security-uncovers-blister-malware-campaign"
        reference_sample = "afb77617a4ca637614c429440c78da438e190dd1ca24dc78483aa731d80832c2"

    strings:
        $a1 = { 8D 45 DC 89 5D EC 50 6A 04 8D 45 F0 50 8D 45 EC 50 6A FF FF D7 }
        $a2 = { 75 F7 39 4D FC 0F 85 F3 00 00 00 64 A1 30 00 00 00 53 57 89 75 }
        $a3 = { 78 03 C3 8B 48 20 8B 50 1C 03 CB 8B 78 24 03 D3 8B 40 18 03 FB 89 4D F8 89 55 E0 89 45 E4 85 C0 74 3E 8B 09 8B D6 03 CB 8A 01 84 C0 74 17 C1 C2 09 0F BE C0 03 D0 41 8A 01 84 C0 75 F1 81 FA B2 17 EB 41 74 27 8B 4D F8 83 C7 02 8B 45 F4 83 C1 04 40 89 4D F8 89 45 F4 0F B7 C0 3B 45 E4 72 C2 8B FE 8B 45 04 B9 }
        $b1 = { 65 48 8B 04 25 60 00 00 00 44 0F B7 DB 48 8B 48 ?? 48 8B 41 ?? C7 45 48 ?? ?? ?? ?? 4C 8B 40 ?? 49 63 40 ?? }
        $b2 = { B9 FF FF FF 7F 89 5D 40 8B C1 44 8D 63 ?? F0 44 01 65 40 49 2B C4 75 ?? 39 4D 40 0F 85 ?? ?? ?? ?? 65 48 8B 04 25 60 00 00 00 44 0F B7 DB }
    condition:
        any of them
}
