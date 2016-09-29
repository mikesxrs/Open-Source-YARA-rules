rule Destructive_Target_Cleaning_Tool_7

{
	meta:
		author = "US CERT"
		reference = "https://www.us-cert.gov/ncas/alerts/TA14-353A"

	strings:
		$ = "SetFilePointer"
		$ = "SetEndOfFile"
		$ = "{75 17 56 ff 15 ?? ?? ?? ?? 6a 00 6a 00 6a 00 56 ffD5 56 ff 15?? ?? ?? ?? 56}"

	condition:
		(uint16(0) == 0x5A4D and uint16(uint32(0x3c)) == 0x4550) and all of them
}
