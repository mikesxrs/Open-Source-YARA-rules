rule Hangover_Gimwup {
    meta:
        author = "Alienvault Labs"
        reference = "https://www.alienvault.com/blogs/labs-research/microsoft-office-zeroday-used-to-attack-pakistani-targets"
    strings:
        $a1 = "=======inside while==========="
        $a2 = "scan finished"
        $a3 = "logFile.txt"
        
    condition:
        all of them

}

