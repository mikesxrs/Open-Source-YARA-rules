rule SparrowDoor_sleep_routine {
meta:
author = "NCSC"
description = "SparrowDoor implements a Sleep routine with value seeded on GetTickCount. This signature detects the previous and this variant of SparrowDoor. No MZ/PE match as the backdoor has no header."
reference = "https://www.ncsc.gov.uk/files/NCSC-MAR-SparrowDoor.pdf"
date = "2022-02-28"
hash1 = "c1890a6447c991880467b86a013dbeaa66cc615f"
strings:
$sleep = {FF D7 33 D2 B9 [4] F7 F1 81 C2 [4] 8B C2 C1 E0 04 2B C2 03 C0 03 C0 03 C0 50}
condition:
all of them
}
