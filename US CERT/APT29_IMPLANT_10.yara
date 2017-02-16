rule IMPLANT_10_v1
{
meta:
	author = "US-CERT"
	description = "ACozyDuke, CozyCar, CozyBear"
	reference = "https://www.us-cert.gov/sites/default/files/publications/AR-17-20045_Enhanced_Analysis_of_GRIZZLY_STEPPE_Activity.pdf"

strings:
	$MZ = "MZ"
	$STR1 = {33 ?? 83 F2 ?? 81 e2 ff 00 00 00}
	$STR2 = {0f be 14 01 33 d0 ?? f2 [1-4] 81 e2 ff 00 00 00 66 89 [6] 40 83 f8 ?? 72}

condition:
	$MZ at 0 and ($STR1 or $STR2)
}

rule IMPLANT_10_v2
{
meta:
	author = "US-CERT"
	description = "ACozyDuke, CozyCar, CozyBear"
	reference = "https://www.us-cert.gov/sites/default/files/publications/AR-17-20045_Enhanced_Analysis_of_GRIZZLY_STEPPE_Activity.pdf"

strings:
	$MZ = "MZ"
	$xor = { 34 ?? 66 33 C1 48 FF C1 }
	$nop = { 66 66 66 66 66 66 0f 1f 84 00 00 00 00 00}

condition:
	$MZ at 0 and $xor and $nop
}
