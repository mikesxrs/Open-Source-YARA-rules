rule gsec_generic
{
meta:
	author = "@patrickrolsen"
	reference = "GSec Dump"
	filetype = "EXE"
	version = "0.1"
	date = "1/29/2014"
strings:
	$s1 = "gsecdump"
	$s2 = "usage: gsecdump"
	$s3 = "dump hashes from SAM//AD"
	$s4 = "dump lsa secrets"
	$s5 = "dump_"
	$s6 = "dump all secrets"
condition:
	uint16(0) == 0x5A4D and (all of ($s*))
}
