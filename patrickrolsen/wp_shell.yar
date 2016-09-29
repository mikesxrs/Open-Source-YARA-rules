rule wp_shell_crew
{
meta:
	author = "@patrickrolsen"
	reference = "http://www.emc.com/collateral/white-papers/h12756-wp-shell-crew.pdf"
	filetype = "EXE"
	version = "0.1"
	date = "1/29/2014"
strings:
	$mz = { 4d 5a } // MZ
	$s1 = "IsWow64Process"
	$s2 = "svchost.exe -k netsvcs"
	$s3 = "Services\\%s\\Parameters"
	$s4 = "%s %s %s"
	$s5 = "-%s-%03d"
	$s6 = "127.0.0.1"
	$s7 = "\\temp\\" fullword
condition:
	($mz at 0) and (all of ($s*))
}
