
private rule IsElfFile {
    condition:
        uint32(0) == 0x464C457F
}

