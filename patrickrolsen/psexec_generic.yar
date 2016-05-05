rule psexec_generic
{
meta:
	author = "@patrickrolsen"
	reference = "Sysinternals PsExec Generic"
	filetype = "EXE"
	version = "0.2"
	date = "1/30/2014"
strings:
	$s1 = "PsInfSvc"
	$s2 = "%s -install"
	$s3 = "%s -remove"
	$s4 = "psexec" nocase
condition:
	uint16(0) == 0x5A4D and (all of ($s*))
}