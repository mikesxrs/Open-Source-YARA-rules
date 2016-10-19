
private rule IsPeFile {
    condition:
        uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x4550
}

