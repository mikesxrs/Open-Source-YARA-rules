rule jiripbot_unicode_str_decrypt 
{ 
	meta: 
		author = "Symantec Security Response"
		date = "2015-07-01"
		description = "Butterfly Jiripbot Unicode hacktool"
        reference ="https://www.symantec.com/content/en/us/enterprise/media/security_response/whitepapers/butterfly-corporate-spies-out-for-financial-gain.pdf"

	strings: 
		$decrypt = {85 ?? 75 03 33 C0 C3 8B ?? 8D 50 02 66 8B 08 83 C0 02 66 85 C9 75 F5 2B C2 D1 F8 57 8B F8 B8 ?? ?? ?? ?? 66 39 44 7E FE 75 43 83 3D ?? ?? ?? ?? 00 53 BB ?? ?? ?? ?? 75 11 53 FF 15 ?? ?? ?? ?? C7 05 ?? ?? ?? ?? 01 00 00 00 53 FF 15 ?? ?? ?? ?? 33 C0 85 FF 74 0E B9 ?? 00 00 00 66 31 0C 46 40 3B C7 72 F2 53 FF 15 ?? ?? ?? ?? 5B 8B C6 5F C3 } 
	condition: 
		$decrypt 
}
