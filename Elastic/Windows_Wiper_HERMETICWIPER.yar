rule Windows_Wiper_HERMETICWIPER {
    meta:
        Author = "Elastic Security"
        creation_date = "2022-02-24"
        last_modified = "2022-02-24"
        os = "Windows"
        arch = "x86"
        category_type = "Wiper"
        family = "HERMETICWIPER"
        threat_name = "Windows.Wiper.HERMETICWIPER"
        description = "Detects HERMETICWIPER used to target Ukrainian organization"
        reference_sample = "1bc44eef75779e3ca1eefb8ff5a64807dbc942b1e4a2672d77b9f6928d292591"
        reference = "https://www.elastic.co/security-labs/elastic-protects-against-data-wiper-malware-targeting-ukraine-hermeticwiper"

    strings:
        $a1 = "\\\\?\\C:\\Windows\\System32\\winevt\\Logs" wide fullword
        $a2 = "\\\\.\\EPMNTDRV\\%u" wide fullword
        $a3 = "tdrv.pdb" ascii fullword
        $a4 = "%s%.2s" wide fullword
        $a5 = "ccessdri" ascii fullword
        $a6 = "Hermetica Digital"
    condition:
        all of them
}
