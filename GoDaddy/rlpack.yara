rule rlpack {
    meta:
        description = "RLPack packed file"
        block = false
        quarantine = false

    strings:
        $mz = "MZ"
        $text1 = ".packed\x00"
        $text2 = ".RLPack\x00"

    condition:
        $mz at 0 and $text1 in (0..1024) and $text2 in (0..1024)
}

