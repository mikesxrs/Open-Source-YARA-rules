rule Hangover_Linog {
    meta:
        author = "Alienvault Labs"
        reference = "https://www.alienvault.com/blogs/labs-research/microsoft-office-zeroday-used-to-attack-pakistani-targets"
    strings:
        $a1 = "uploadedfile"
        $a2 = "Error in opening a file.."
        $a3 = "The file could not be opened"
        $a4 = "%sContent-Disposition: form-data; name=\"%s\";filename=\"%s\""

    condition:
        all of them

}


