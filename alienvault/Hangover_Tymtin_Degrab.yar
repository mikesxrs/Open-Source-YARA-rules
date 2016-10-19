rule Hangover_Tymtin_Degrab {
    meta:
         author = "Alienvault Labs"
         reference = "https://www.alienvault.com/blogs/labs-research/microsoft-office-zeroday-used-to-attack-pakistani-targets"
    strings:
        $a1 = "&dis=no&utp=op&mfol="
        $a2 = "value1=1&value2=2"
        
    condition:
        all of them

}


