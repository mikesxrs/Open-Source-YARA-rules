rule jiripbot_ascii_str_decrypt 
{ 
	meta: 
		author ="Symantec Security Response"
		date ="2015-07-01" 
		description ="Butterfly Jiripbot hacktool" 
		reference ="https://www.symantec.com/content/en/us/enterprise/media/security_response/whitepapers/butterfly-corporate-spies-out-for-financial-gain.pdf"
	strings: 
		$decrypt_func = {85 FF 75 03 33 C0 C3 8B C7 8D 50 01 8A 08 40 84 C9 75 F9 2B C2 53 8B D8 80 7C 3B FF ?? 75 3E 83 3D ?? ?? ?? ?? 00 56 BE ?? ?? ?? ?? 75 11 56 FF 15 ?? ?? ?? ?? C7 05 ?? ?? ?? ?? 01 00 00 00 56 FF 15 ?? ?? ?? ?? 33 C0 85 DB 74 09 80 34 38 ?? 40 3B C3 72 F7 56 FF 15 ?? ?? ?? ?? 5E 8B C7 5B C3} 
	condition: 
		$decrypt_func 
}