rule Hangover2_backdoor_shell {
    meta:
        author = "Alienvault Labs"
        reference = "https://www.alienvault.com/blogs/labs-research/microsoft-office-zeroday-used-to-attack-pakistani-targets"

  strings:

    $a = "Shell started at: " wide ascii

    $b = "Shell closed at: " wide ascii

    $c = "Shell is already closed!" wide ascii

    $d = "Shell is not Running!" wide ascii

  condition:

    all of them
}