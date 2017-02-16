rule IMPLANT_9_v1
{
meta:
	author = "US-CERT"
	description = "APT29  OnionDuke"
	reference = "https://www.us-cert.gov/sites/default/files/publications/AR-17-20045_Enhanced_Analysis_of_GRIZZLY_STEPPE_Activity.pdf"

strings:
	$STR1 = { 8B 03 8A 54 01 03 32 55 FF 41 88 54 39 FF 3B CE 72 EE }
	$STR2 = { 8B C8 83 E1 03 8A 54 19 08 8B 4D 08 32 54 01 04 40 88 54 38 FF 3B C6 72 E7 }
	$STR3 = { 8B 55 F8 8B C8 83 E1 03 8A 4C 11 08 8B 55 FC 32 0C 10 8B 17 88 4C 02 04 40 3B 06 72 E3 }

condition:
	(uint16(0) == 0x5A4D or uint16(0)) and all of them
}
