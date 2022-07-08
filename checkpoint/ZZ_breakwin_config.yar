rule ZZ_breakwin_config {
    meta:
        description = "Detects the header of the encrypted config files, assuming known encryption key."
        reference = "https://research.checkpoint.com/2021/indra-hackers-behind-recent-attacks-on-iran/"
        author = "Check Point Research"
        date = "22-07-2021"
        hash = "948febaab71727217303e0aabb9126f242aa51f89caa7f070a3da76c4f5699ed"
        hash = "2d35bb7c02062ff2fba4424a267c5c83351405281a1870f52d02f3712a547a22"
        hash = "68e95a3ccde3ea22b8eb8adcf0ad53c7993b2ea5316948e31d9eadd11b5151d7"
    strings:
        $conf_header = {1A 69 45 47 5E 46 4A 06 03 E4 34 0B 06 1D ED 2F 02 15 02 E5 57 4D 59 59 D1 40 20 22}
    condition:
        $conf_header at 0
}
