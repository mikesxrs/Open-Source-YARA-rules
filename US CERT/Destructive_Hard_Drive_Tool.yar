import "pe"
rule Destructive_Hard_Drive_Tool

{
	meta:
		author = "US CERT"
		reference = "https://www.us-cert.gov/ncas/alerts/TA14-353A"

	strings:

		$str0= "MZ"

		$str1 = {c6 84 24 ?? ( 00 | 01 ) 00 00 }

		$xorInLoop = { 83 EC 20 B9 08 00 00 00 33 D2 56 8B 74 24 30 57 8D 7C 24 08 F3 A5 8B 7C 24 30 85 FF 7E 3A 8B 74 24 2C 8A 44 24 08 53 8A 4C 24 21 8A 5C 24 2B 32 C1 8A 0C 32 32 C3 32 C8 88 0C 32 B9 1E 00 00 00 8A 5C 0C 0C 88 5C 0C 0D 49 83 F9 FF 7F F2 42 88 44 24 0C 3B D7 7C D0 5B 5F 5E 83 C4 20 C3 }

	condition:

		$str0 at 0 and $xorInLoop and #str1 > 300

}