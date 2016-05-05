rule procdump
{
meta:
	author = "@patrickrolsen"
	reference = "Procdump"
	filetype = "EXE"
	version = "0.1"
	date = "1/30/2014"
strings:
	$s1 = "\\Procdump\\"
	$s2 = "procdump"
	$s3 = "Process"
condition:
	uint16(0) == 0x5A4D and (all of ($s*))
}