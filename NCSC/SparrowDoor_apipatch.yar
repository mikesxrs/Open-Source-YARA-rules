rule SparrowDoor_apipatch {
meta:
author = "NCSC"
description = "Identifies code segments in SparrowDoor responsible for patching APIs. No MZ/PE match as the backdoor has no header. Targeting in memory."
reference = "https://www.ncsc.gov.uk/files/NCSC-MAR-SparrowDoor.pdf"
date = "2022-02-28"
hash1 = "c1890a6447c991880467b86a013dbeaa66cc615f"
strings:
$save = {8B 06 89 07 8A 4E 04} // save off first 5 bytes of function
$vp_1 = {89 10 8A 4E 04 8B D6 2B D0 88 48 04 83 EA 05 C6 40 05 E9 89 50 06} // calculate long jump
$vp_2 = {50 8B D6 6A 40 2B D7 88 4F 04 83 EA 05 6A 05 C6 47 05 E9 89 57 06 56} // calculate long jump 2
$vp_3 = {51 52 2B DE 6A 05 83 EB 05 56 C6 06 E9 89 5E 01} // restore memory protections
$va = {6A 40 68 00 10 00 00 68 00 10 00 00 6A 00} // virtually alloc set size, allocation and protection
$s_patch = {50 68 7F FF FF FF 68 FF FF 00 00 56} // socket patch SO_DONTLINGER
condition:
3 of them
}
