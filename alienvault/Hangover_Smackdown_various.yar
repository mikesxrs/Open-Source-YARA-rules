rule Hangover_Smackdown_various {
    meta:
        author = "Alienvault Labs"
        reference = "https://www.alienvault.com/blogs/labs-research/microsoft-office-zeroday-used-to-attack-pakistani-targets"
    strings:
        $a1 = "pranVacrhan"
        $a2 = "NaramGaram"
        $a3 = "vampro"
        $a4 = "AngelPro"
        
        $b1 = "VBA6.DLL"
        $b2 = "advpack"
        $b3 = "IsNTAdmin"
        
        
    condition:
        1 of ($a*) and all of ($b*)

}

