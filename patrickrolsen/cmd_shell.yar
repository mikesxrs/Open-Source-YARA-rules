rule cmd_shell
{
meta:
	author = "@patrickrolsen"
	reference = "Windows CMD Shell"
	filetype = "EXE"
	version = "0.1"
	date = "1/30/2014"
strings:
	$s1 = "cmd.pdb"
	$s2 = "CMD Internal Error %s"
condition:
	uint16(0) == 0x5A4D and (all of ($s*)) and filesize <= 380KB
}