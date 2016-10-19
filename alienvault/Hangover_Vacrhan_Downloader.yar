rule Hangover_Vacrhan_Downloader {
    meta:
        author = "Alienvault Labs"
        reference = "https://www.alienvault.com/blogs/labs-research/microsoft-office-zeroday-used-to-attack-pakistani-targets"
    strings:
        $a1 = "pranVacrhan"
        $a2 = "VBA6.DLL"
        $a3 = "Timer1"
        $a4 = "Timer2"
        $a5 = "IsNTAdmin"
        
    condition:
        all of them

}


