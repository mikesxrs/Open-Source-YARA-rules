rule SparrowDoor_config {
meta:
author = "NCSC"
description = "Targets the XOR encoded loader config and shellcode in the file libhost.dll using the known position of the XOR key."
reference = "https://www.ncsc.gov.uk/files/NCSC-MAR-SparrowDoor.pdf"
date = "2022-02-28"
hash1 = "c1890a6447c991880467b86a013dbeaa66cc615f"
condition:
(uint16(0) != 0x5A4D) and
(uint16(0) != 0x8b55) and
(uint32(0) ^ uint32(0x4c) == 0x00) and
(uint32(0) ^ uint32(0x34) == 0x00) and
(uint16(0) ^ uint16(0x50) == 0x8b55)
}
