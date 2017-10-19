
import "pe"

rule hkdoor_backdoor_dll {
    meta:
        author = "Cylance"
        description = "Hacker's Door Backdoor DLL"
        reference = "https://www.cylance.com/en_us/blog/threat-spotlight-opening-hackers-door.html"

    strings:
        $s1 = "The version of personal hacker's door server is" fullword ascii
        $s2 = "The connect back interval is %d (minutes)" fullword ascii
        $s3 = "I'mhackeryythac1977" fullword ascii
        $s4 = "Welcome to http://www.yythac.com" fullword ascii
        $s5 = "SeLoadDriverPrivilege" fullword ascii

    condition:
        uint16(0) == 0x5a4d and filesize < 400KB and ( 3 of ($s*) ) and pe.characteristics & pe.DLL and pe.imports("ws2_32.dll", "WSAStartup") and pe.imports("ws2_32.dll", "sendto")
}



