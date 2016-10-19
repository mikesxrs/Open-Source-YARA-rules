rule Hangover_Fuddol {
    meta:
        author = "Alienvault Labs"
        referemce = "https://www.alienvault.com/blogs/labs-research/microsoft-office-zeroday-used-to-attack-pakistani-targets"
    strings:
        $a = "\\Http downloader(fud)"
        $b = "Fileexists"
    condition:
        all of them

}

