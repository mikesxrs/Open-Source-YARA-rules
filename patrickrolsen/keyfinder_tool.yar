rule keyfinder_tool
{
meta:
	author = "@patrickrolsen"
	reference = "Magical Jelly Bean KeyFinder"
strings:
	$s1 = "chgxp.vbs"
	$s2 = "officekey.exe"
	$s3 = "findkey.exe"
	$s4 = "xpkey.exe"
condition:
	uint16(0) == 0x5A4D and 2 of ($s*)
}