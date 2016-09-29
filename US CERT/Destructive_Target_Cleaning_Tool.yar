/*
rule Destructive_Target_Cleaning_Tool
{
	meta:
		author = "US CERT"
		reference = "https://www.us-cert.gov/ncas/alerts/TA14-353A"

	strings:
		$s1  = {d3000000 [4] 2c000000 [12] 95000000 [4] 6a000000 [8] 07000000}

	condition:
		(uint16(0) == 0x5A4D and uint16(uint32(0x3c)) == 0x4550) and all of them

}
*/