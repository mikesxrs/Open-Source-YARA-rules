rule nbtscan
{
meta:
	author = "@patrickrolsen"
	reference = "nbtscan"
	filetype = "EXE"
	version = "0.1"
	date = "1/30/2014"
strings:
	$s1 = "nbtscan" nocase
	$s2 = "subnet /%d"
	$s3 = "invalid target"
	$s4 = "usage: %s"
condition:
	uint16(0) == 0x5A4D and (all of ($s*))
}