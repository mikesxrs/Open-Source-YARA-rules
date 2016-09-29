rule blat_email_301
{
meta:
	author = "@patrickrolsen"
strings:
	$s1 = {33 00 2E 00 30 00 2E 00 31} // 301 uni
	$s2 = "Mar  7 2012"
condition:
	uint16(0) == 0x5A4D and (all of ($s*))
}
