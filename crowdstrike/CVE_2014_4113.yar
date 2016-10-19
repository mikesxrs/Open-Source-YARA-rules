rule CrowdStrike_CVE_2014_4113 {
meta:
	copyright = "CrowdStrike, Inc"
	description = "CVE-2014-4113 Microsoft Windows x64 Local Privilege Escalation Exploit"
	version = "1.0"
	last_modified = "2014-10-14"
	in_the_wild = true
strings:
	$const1 = { fb ff ff ff }
	$const2 = { 0b 00 00 00 01 00 00 00 }
	$const3 = { 25 00 00 00 01 00 00 00 }
	$const4 = { 8b 00 00 00 01 00 00 00 }
condition:
	all of them
}