rule Hangover_Deksila {
    meta:
        author = "Alienvault Labs"
        reference = "https://www.alienvault.com/blogs/labs-research/microsoft-office-zeroday-used-to-attack-pakistani-targets"
    strings:
        $a1 = "WinInetGet/0.1"
        $a2 = "dekstop2007.ico"
        $a3 = "mozila20"
        
    condition:
        all of them

}

