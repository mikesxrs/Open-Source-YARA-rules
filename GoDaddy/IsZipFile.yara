
private rule IsZipFile {
    condition:
        uint16(0) == 0x4B50
}

