rule IMPLANT_7_v1
{
meta:
	author = "US-CERT"
	description = "APT29 implant7"
	reference = "https://www.us-cert.gov/sites/default/files/publications/AR-17-20045_Enhanced_Analysis_of_GRIZZLY_STEPPE_Activity.pdf"

strings:
	$MZ = "MZ"
	$STR1 = { 8A 44 0A 03 32 C3 0F B6 C0 66 89 04 4E 41 3B CF 72 EE }
	$STR2 = { F3 0F 6F 04 08 66 0F EF C1 F3 0F 7F 04 11 83 C1 10 3B CF 72 EB }

condition:
	$MZ at 0 and ($STR1 or $STR2)
}
