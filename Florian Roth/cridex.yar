rule Malware_Cridex_Generic {
meta:
        description = "Rule matching Cridex-C Malware distributed in a German Campaign, January 2014 (Vodafone, Telekom, Volksbank bills)"
        author = "F. Roth"
        date = "2014-01-15"
        reference = "https://www.virustotal.com/en/file/519120e4ff6524353247dbac3f66e6ddad711d384e317923a5bb66c16601743e/analysis/"
        hash = "86d3e008b8f5983c374a4859739f7de4"
strings:
        $c1 = "NEWDEV.dll" fullword
        $b2a = "COMUID.dll" fullword
        $b2b = "INSENG.dll" fullword
condition:
        $c1 and 1 of ($b*)
}
