import "pe"    

    rule Mal_Win32_ChaosRansomware_2022
{            
    meta:
    description = "Detects Ransomware Built by Chaos Ransomware Builder"
    reference = "https://blogs.blackberry.com/en/2022/05/yashma-ransomware-tracing-the-chaos-family-tree"
    author = "BlackBerry Threat Research"
    date = "2022-05-10"
    license = "This Yara rule is provided under the Apache License 2.0 (https://www.apache.org/licenses/LICENSE-2.0) and open to any user or organization, as long as you use it under this license and ensure originator credit in any derivative to The BlackBerry Research & Intelligence Team"

    strings:
        //Ransom References
        $x1 = "Encrypt" ascii wide
        $x2 = "(?:[13]{1}[a-km-zA-HJ-NP-Z1-9]{26,33}|bc1[a-z0-9]{39,59})" ascii wide
        $x3 = "read" ascii wide        

        //Ransom Hex
        $r1 = { 20 76 69 72 75 73 }
        $r2 = { 72 00 61 00 6e 00 73 00 6f 00 6d 00 77 00 61 00 72 00 65 }

        //Shadow Copy Delete
        $z0 = "deleteShadowCopies" ascii wide
        $z1 = "shadowcopy" ascii wide

      condition:

        //PE File
        uint16(0) == 0x5a4d and

        // Must be less than
        filesize < 35KB and

        // Must have exact import hash
        pe.imphash() == "f34d5f2d4577ed6d9ceec516c1f5a744" and

        //Number of sections
        pe.number_of_sections == 3 and

        //These Strings
        ((all of ($x*)) and (1 of ($r*)) and (1 of ($z*)))

 

}


