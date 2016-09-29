private rule isPE
{
	meta:
		Author = "Symantec"
		Reference = "https://www.symantec.com/content/en/us/enterprise/media/security_response/whitepapers/Dragonfly_Threat_Against_Western_Energy_Suppliers.pdf"

 	condition:
 		uint16(0) == 0x5A4D and uint32(uint32(0x3c)) == 0x00004550
}