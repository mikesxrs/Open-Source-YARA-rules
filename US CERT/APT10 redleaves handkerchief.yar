rule REDLEAVES_DroppedFile_ObfuscatedShellcodeAndRAT_handkerchief {
    meta:
        description = "Detect obfuscated .dat file containing shellcode and core REDLEAVES RAT"
        author = "USG"
        true_positive = "fb0c714cd2ebdcc6f33817abe7813c36" // handkerchief.dat
        reference = "https://www.us-cert.gov/ncas/alerts/TA17-117A"

    strings:
        $RedleavesStringObfu = {73 64 65 5e 60 74 75 74 6c 6f 60 6d 5e 6d 64 60 77 64 72 5e 65 6d 6d 6c 60 68 6f 2f 65 6d 6d} // This is 'red_autumnal_leaves_dllmain.dll' XOR'd with 0x01
    condition:
        any of them
}
