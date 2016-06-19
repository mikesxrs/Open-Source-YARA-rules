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