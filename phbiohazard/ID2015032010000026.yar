rule ID2015032010000026
{
meta:
author = "mbl"
info = "IOC detection - Version 1.0"
reference = "https://github.com/phbiohazard/Yara"
	strings:
		$genep1 = {4D 5A 90 00 03 00}	
		$contep1 = {4D D0 FF EB 22 C7 85 78 FF FF FF 1C 00 00 00 EB}
		$contep2 = {2F 77 77 77 2E 74 68 61 77 74 65 2E 63 6F 6D 2F}

	condition:
		$genep1 and ($contep1 in (0x5d90..0x5d9f) and $contep2 in (0x27e70..0x27e7f))

}