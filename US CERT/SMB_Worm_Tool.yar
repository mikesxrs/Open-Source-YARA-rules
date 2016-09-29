rule SMB_Worm_Tool

{

	meta:
		author = "US CERT"
		reference = "https://www.us-cert.gov/ncas/alerts/TA14-353A"

    strings:

		$STR1 = "Global\\FwtSqmSession106829323_S-1-5-19"
		$STR2 ="EVERYONE"
		$STR3 = "y0uar3@s!llyid!07,ou74n60u7f001"
		$STR4 = "\\KB25468.dat" 

	condition:
		(uint16(0) == 0x5A4D or uint16(0) == 0xCFD0 or uint16(0) ==0xC3D4 or uint32(0) == 0x46445025 or uint32(1) == 0x6674725C) and all of them
}