rule scanline_mcafee
{
meta:
	author = "@patrickrolsen"
	reference = "http://www.mcafee.com/us/downloads/free-tools/scanline.aspx"
	filetype = "EXE"
	version = "0.1"
	date = "1/30/2014"
strings:
	$s1 = "CPports.txt"
	$s2 = "ICMP Time"
	$s3 = "Foundsto"
	$s4 = "USER"
	$s5 = {55 50 58 ??} // UPX?
condition:
	uint16(0) == 0x5A4D and (all of ($s*))
}