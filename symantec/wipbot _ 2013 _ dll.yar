rule wipbot_2013_dll 
{
 	meta:
 		author = "Symantec"
		description = "Trojan.Wipbot 2013 DLL"
		reference = "https://www.symantec.com/content/en/us/enterprise/media/security_response/whitepapers/waterbug-attack-group.pdf"
 		description = "Down.dll component"
        
 	strings:
		$string1 = "/%s?rank=%s"
		$string2 = "ModuleStart\x00ModuleStop\x00start"
		$string3 = "1156fd22-3443-4344-c4ffff"
		//read file... error..
		$string4 = "read\x20file\x2E\x2E\x2E\x20error\x00\x00"

	condition:
		2 of them
}