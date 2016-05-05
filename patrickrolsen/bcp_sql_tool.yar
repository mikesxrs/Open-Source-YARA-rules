rule bcp_sql_tool
{
meta:
	author = "@patrickrolsen"
	reference = "iSIGHTPartners_ThreatScape_AA_KAPTOXA PDF - 3f00dd56b1dc9d9910a554023e868dac"
	filetype = "EXE"
	version = "0.1"
	date = "1/30/2014"
strings:
	$s1 = "BCP" nocase
	$s2 = "SQLState = %s"
	$s3 = "Warning = %s"
	$s5 = ";database="
	$s6 = "FIRE_TRIGGERS"

condition:
	uint16(0) == 0x5A4D and (all of ($s*))
}
