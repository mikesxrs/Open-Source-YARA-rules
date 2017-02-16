rule IMPLANT_12_v1
{
meta:
	author = "US-CERT"
	description = "CosmicDuke"
	reference = "https://www.us-cert.gov/sites/default/files/publications/AR-17-20045_Enhanced_Analysis_of_GRIZZLY_STEPPE_Activity.pdf"

strings:
	$FUNC = {a1 [3-5] 33 c5 89 [2-3] 56 57 83 [4-6] 64}

condition:
	(uint16(0) == 0x5A4D) and $FUNC
}
