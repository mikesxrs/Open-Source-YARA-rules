rule monitor_tool_pos
{
meta:
	author = "@patrickrolsen"
	reference = "POS malware - Monitoring Tool??"
strings:
	$s1 = "RCPT TO"
	$s2 = "MAIL FROM"
	$s3 = "AUTH LOGIN"
	$s4 = "Reply-To"
	$s5 = "X-Mailer"
	$s6 = "crypto"
	$s7 = "test335.txt" wide
	$s8 = "/c del"
condition:
	uint16(0) == 0x5A4D and 7 of ($s*)
}