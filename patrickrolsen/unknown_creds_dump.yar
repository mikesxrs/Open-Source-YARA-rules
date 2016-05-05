rule unknown_creds_dump
{
meta:
	author = "@patrickrolsen"
	reference = "Misc. Creds Dump"
	filetype = "EXE"
	version = "0.1"
	date = "1/30/2014"
strings:
	$s1 = "OpenProcessToken:%d"
	$s2 = "LookupPrivilegeValue:%d"
	$s3 = "AdjustTokenPrivilege:%d"
	$s4 = "\\GetPassword\\"
condition:
	uint16(0) == 0x5A4D and (all of ($s*))
}