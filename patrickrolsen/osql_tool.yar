rule osql_tool
{
meta:
	author = "@patrickrolsen"
	reference = "O/I SQL - SQL query tool"
	filetype = "EXE"
	version = "0.1"
	date = "1/30/2014"
strings:
	$s1 = "osql\\src"
	$s2 = "OSQLUSER"
	$s3 = "OSQLPASSWORD"
	$s4 = "OSQLSERVER"
condition:
	uint16(0) == 0x5A4D and (all of ($s*))
}
