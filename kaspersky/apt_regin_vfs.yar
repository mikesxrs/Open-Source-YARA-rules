rule apt_regin_vfs {

meta:

	copyright = "Kaspersky Lab"
	description = "Rule to detect Regin VFSes"
	version = "1.0"
	last_modified = "2014-11-18"
	Reference = "https://securelist.com/files/2014/11/Kaspersky_Lab_whitepaper_Regin_platform_eng.pdf"

strings:

	$a1={00 02 00 08 00 08 03 F6 D7 F3 52}
	$a2={00 10 F0 FF F0 FF 11 C7 7F E8 52}
	$a3={00 04 00 10 00 10 03 C2 D3 1C 93}
	$a4={00 04 00 10 C8 00 04 C8 93 06 D8}

condition:

	($a1 at 0) or ($a2 at 0) or ($a3 at 0) or ($a4 at 0)
}
