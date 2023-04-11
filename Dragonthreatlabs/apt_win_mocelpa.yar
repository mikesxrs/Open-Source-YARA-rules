 rule apt_win_mocelpa {
meta:
     author = "@int0x00"
     description = "APT malware; Mocelpa, downloader."
     report = "https://github.com/DragonThreatLabs/IntelReports/blob/master/DTL-06282015-01.pdf"
strings:
     $mz = {4D 5A}
     $ssl_hello = {16 03 01 00 6B 01 00 00 67 03 01 54 B4 C9 7B 4F CF BC 5A 01 EC 4A 73 C8 6D BB C0 86 9F 7B A9 08 6A 60 37 05 81 97 1A C8 9F 45 E5 00 00 18 00 2F 00 35 00 05 00 0A C0 13 C0 14 C0 09 C0 0A 00 32 00 38 00 13 00 04 01 00 00 26 00 00 00 12 00 10 00 00 0D 77 77 77 2E 61 70 70 6C 65 2E 63 6F 6D 00 0A 00 06 00 04 00 17 00 18 00 0B 00 02 01 00}
condition:
     ($mz at 0) and ($ssl_hello)
}
