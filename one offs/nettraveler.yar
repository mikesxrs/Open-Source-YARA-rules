/*
  Rules generated from APT Report NetTraveler
  http://www.securelist.com/en/blog/8105/NetTraveler_is_Running_Red_Star_APT_Attacks_Compromise_High_Profile_Victims
*/
rule APT_Malware_BAT_Contents {
        meta: description = "APT Malware Batch File Contents" threat_level = 10 score = 60
        strings:
        $a1 = ">nul del"
        $a2 = "service.exe"
        $a3 = "service.dll"
        condition: all of them
}
rule APT_Malware_NetTraveler_Saker {
        meta: description = "APT Malware NetTraveler Saker" threat_level = 10 score = 50
        strings:
        $a1 = "JustTempFun" fullword
        $a2 = "servicemain" nocase fullword
        condition: all of them
}
rule APT_Malware_NetTraveler_Trojan {
        meta: description = "APT Malware NetTraveler Trojan" threat_level = 10 score = 65
        strings:
        $a1 = "Get From IEOption!"
        $a2 = "Get From Reg!"
        condition: all of them
}
