rule Hangover_Iconfall {
    meta:
        author = "Alienvault Labs"
        reference = "https://www.alienvault.com/blogs/labs-research/microsoft-office-zeroday-used-to-attack-pakistani-targets"
    strings:
        $a1 = "iconfall"
        $a2 = "78DDB5A902BB8FFF3F398B45BEDCD152"
        
    condition:
        all of them

}


