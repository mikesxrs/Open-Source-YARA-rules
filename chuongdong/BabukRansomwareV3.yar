rule BabukRansomwareV3 {
    meta:
        description = "YARA rule for Babuk Ransomware v3"
        reference = "http://chuongdong.com/reverse%20engineering/2021/01/16/BabukRansomware-v3/"
        author = "@cPeterr"
        date = "2021-01-16"
        rule_version = "v3"
        malware_type = "ransomware"
        tlp = "white"
    strings:
        $lanstr1 = "-lanfirst"
        $lanstr2 = "-nolan"
        $lanstr3 = "shares"
        $str1 = "BABUK LOCKER"
        $str2 = "babukq4e2p4wu4iq.onion"
        $str3 = "How To Restore Your Files.txt" wide
        $str4 = "babuk_v3"
        $str5 = ".babyk" wide
    condition:
        all of ($str*) and all of ($lanstr*)
}
