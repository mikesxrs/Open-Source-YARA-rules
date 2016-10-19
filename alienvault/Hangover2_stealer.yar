rule Hangover2_stealer {
    meta:
        author = "Alienvault Labs"
        reference = "https://www.alienvault.com/blogs/labs-research/microsoft-office-zeroday-used-to-attack-pakistani-targets"

  strings:

    $a = "MyWebClient" wide ascii

    $b = "Location: {[0-9]+}" wide ascii

    $c = "[%s]:[C-%s]:[A-%s]:[W-%s]:[S-%d]" wide ascii

  condition:

    all of them
}

