rule Lightweight_Backdoor_2

{

	meta:
		author = "US CERT"
		reference = "https://www.us-cert.gov/ncas/alerts/TA14-353A"

	strings:
		$STR1 = "prxTroy" ascii wide nocase

	condition:
		(uint16(0) == 0x5A4D or uint16(0) == 0xCFD0 or uint16(0) == 0xC3D4 or uint32(0) == 0x46445025 or uint32(1) == 0x6674725C) and all of them

}