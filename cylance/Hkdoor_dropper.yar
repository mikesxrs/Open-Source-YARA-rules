import "pe"

rule hkdoor_dropper {
    meta:
        description = "Hacker's Door Dropper"
        author = "Cylance"
        reference = "https://www.cylance.com/en_us/blog/threat-spotlight-opening-hackers-door.html"

    strings:
        $s1 = "The version of personal hacker's door server is" fullword ascii
        $s2 = "The connect back interval is %d (minutes)" fullword ascii
        $s3 = "I'mhackeryythac1977" fullword ascii
        $s4 = "Welcome to http://www.yythac.com" fullword ascii
        $s5 = "SeLoadDriverPrivilege" fullword ascii
        $s6 = "\\drivers\\ntfs.sys" fullword ascii
        $s7 = "kifes" fullword ascii

    condition:
        uint16(0) == 0x5a4d and
        filesize < 1000KB and
        ( 4 of ($s*) ) and
        pe.number_of_resources > 0 and
        for any i in (0..pe.number_of_resources - 1):
            (pe.resources[i].type_string == "B\x00I\x00N\x00" and
            uint16(pe.resources[i].offset) == 0x5A4D) and
        pe.imports("KERNEL32.dll", "FindResourceW") and
        pe.imports("KERNEL32.dll", "LoadResource")
}
