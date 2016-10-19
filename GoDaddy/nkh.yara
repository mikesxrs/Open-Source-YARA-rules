
rule nkh_packer {
    meta:
        block = false
        quarantine = false
    strings:
        // payload is xor compressed in the overlay with a 4-byte xor key
        $nkh_section = ".nkh_\x00\x00\x00\x00\x10\x00\x00"

    condition:
        IsPeFile and $nkh_section in (0..0x400)
}

