import "pe"

rule APT20140414_1NT
{
	meta:
		author = "phbiohazard"
		reference = "https://github.com/phbiohazard/Yara"
	strings:
		$dpi1 = {47 45 54 20 2f}
		$dpi2 = {2F 74 61 73 6B 73 3F 76 65 72 73 69 6F 6E 3D}
		$dpi3 = {26 67 72 6F 75 70 3D}
		$dpi4 = {26 63 6C 69 65 6E 74 3D}
	condition:
		all of them
}

rule APT20140414_1PE
{
meta:
	author = "phbiohazard"
	reference = "https://github.com/phbiohazard/Yara"

strings:
    $genep1 = {04 01 68 9b 1a 40 00 6a 01 6a 00 6a 00 ff 15 0c}
    $genep2 = {e9 3d 87 f8 ff bb d6 fb 04 8a 10 5c d2 70 d9 cb}
    $genep3 = {57 56 8b f0 e8 70 fd ff ff 5e e8 6e 01 00 00 5f}
    $contep1 = {e9 02 47 83 c6 02 89 f2 83 f9 00}
    $contep2 = {e5 44 75 c1 8b 36 0c 44 4d c9 31 8b 8a d7 88 d8}
    $contep3 = {9c d1 d4 52 7b c5 99 29 1c d7 46 c5 f9 8c f8 e2}
    $contep4 = {e8 ef e4 bb 00 5d c3}
condition:
    $genep1 and $contep1 and $contep2 or ($genep2 at pe.entry_point and ($contep3 in (pe.entry_point..pe.entry_point + 65))) or ($genep3 at pe.entry_point and ($contep4 in (pe.entry_point..pe.entry_point + 26)))

}

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