rule winrar_4xx
{
meta:
	author = "@patrickrolsen"
	reference = "WinRar 4.11 CMD line version"
	filetype = "EXE"
	version = "0.1"
	date = "1/30/2014"
strings:
	$s1 = "\\WinRAR\\rar\\"
	$s2 = "WinRAR"
condition:
	uint16(0) == 0x5A4D and (all of ($s*))
}
