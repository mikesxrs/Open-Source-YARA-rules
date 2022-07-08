rule SparrowDoor_shellcode {
meta:
author = "NCSC"
description = "Targets code features of the reflective loader for SparrowDoor. Targeting in memory."
reference = "https://www.ncsc.gov.uk/files/NCSC-MAR-SparrowDoor.pdf"
date = "2022-02-28"
hash1 = "c1890a6447c991880467b86a013dbeaa66cc615f"
strings:
$peb = {8B 48 08 89 4D FC 8B 51 3C 8B 54 0A 78 8B 74 0A 20 03 D1 03 F1 B3 64}
$getp_match = {8B 06 03 C1 80 38 47 75 34 80 78 01 65 75 2E 80 78 02 74 75 28 80 78 03 50 75 22 80 78 04 72 75 1C 80 78 06 63 75 16 80 78 05 6F 75 10 80 78 07 41 75 0A}
$k_check = {8B 48 20 8A 09 80 F9 6B 74 05 80 F9 4B 75 05}
$resolve_load_lib = {C7 45 C4 4C 6F 61 64 C7 45 C8 4C 69 62 72 C7 45 CC 61 72 79 41 C7 45 D0 00 00 00 00 FF 75 FC FF 55 E4}
condition:
3 of them
}
