import "pe"

rule SparrowDoor_clipshot {
meta:
author = "NCSC"
description = "The SparrowDoor loader contains a feature it calls clipshot, which logs clipboard data to a file."
reference = "https://www.ncsc.gov.uk/files/NCSC-MAR-SparrowDoor.pdf"
date = "2022-02-28"
hash1 = "989b3798841d06e286eb083132242749c80fdd4d"
strings:
$exsting_cmp = {8B 1E 3B 19 75 ?? 83 E8 04 83 C1 04 83 C6 04 83 F8 04} // comparison routine for previous clipboard data
$time_format_string = "%d/%d/%d %d:%d" ascii
$cre_fil_args = {6A 00 68 80 00 00 00 6A 04 6A 00 6A 02 68 00 00 00 40 52}
condition:
(uint16(0) == 0x5A4D) and uint32(uint32(0x3C)) == 0x00004550 and
all of them and (pe.imports("User32.dll","OpenClipboard") and
pe.imports("User32.dll","GetClipboardData") and
pe.imports("Kernel32.dll","GetLocalTime") and
pe.imports("Kernel32.dll","GlobalSize"))
}
