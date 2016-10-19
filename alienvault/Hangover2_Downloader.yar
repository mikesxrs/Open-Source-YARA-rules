rule Hangover2_Downloader {
    meta:
        author = "Alienvault Labs"
        reference = "https://www.alienvault.com/blogs/labs-research/microsoft-office-zeroday-used-to-attack-pakistani-targets"

  strings:

    $a = "WinInetGet/0.1" wide ascii

    $b = "Excep while up" wide ascii

    $c = "&file=" wide ascii

    $d = "&str=" wide ascii

    $e = "?cn=" wide ascii

  condition:

    all of them
}

