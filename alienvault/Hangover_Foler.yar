rule Hangover_Foler {
    meta:
        author = "Alienvault Labs"
        reference = "https://www.alienvault.com/blogs/labs-research/microsoft-office-zeroday-used-to-attack-pakistani-targets"
    strings:
        $a1 = "\\MyHood"
        $a2 = "UsbP"
        $a3 = "ID_MON"
        
    condition:
        all of them

}

