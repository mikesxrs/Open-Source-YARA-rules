rule Lightweight_Backdoor_3

{

	meta:
		author = "US CERT"
		reference = "https://www.us-cert.gov/ncas/alerts/TA14-353A"

	strings:

		$strl  = "{ C6 45 E8 64 C6 45 E9 61 C6 45 EA 79 C6 45 EB 69 C6 45 EC 70 C6 45 ED 6D C6 45 EE 72 C6 45 EF 2E C6 45 F0 74 C6 45 F1  62 C6 45 F2 6C }" // 'dayipmr.tbl' being moved to ebp

	condition:
		(uint16(0) == 0x5A4D or uint16(0) == 0xCFD0 or uint16(0) == 0xC3D4 or uint32(0) == 0x46445025 or uint32(1) == 0x6674725C) and all of them
}