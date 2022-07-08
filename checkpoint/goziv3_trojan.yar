rule goziv3: trojan {
    meta:
        module = "goziv3"
        reference = "https://research.checkpoint.com/2020/gozi-the-malware-with-a-thousand-faces/"
    strings:
        $dec_bss = {D3 C0 83 F3 01 89 02 83 C2 04 FF 4C 24 0C}
        $gen_serpent = {33 44 24 04 33 44 24 08 C2 08 00}
    condition:
        ($dec_bss and $gen_serpent) and (uint16(0) == 0x5A4D  or uint16(0) == 0x5850  )
}

