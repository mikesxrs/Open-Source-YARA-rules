rule wipbot_2013_core 
{
 	meta:
 		description = "core + core; garbage appended data (PDF Exploit leftovers) + wipbot dropper; fake AdobeRd32 Error"
 		Malware = "Trojan.Wipbot 2013 core component"
 		author = "Symantec"
 		reference = "https://www.symantec.com/content/en/us/enterprise/media/security_response/whitepapers/waterbug-attack-group.pdf"

 	strings:
 		$mz = "MZ"
	/*
 	8947 0C MOV DWORD PTR DS:[EDI+C], EAX
 	C747 10 90C20400 MOV DWORD PTR DS:[EDI+10], 4C290
 	C747 14 90C21000 MOV DWORD PTR DS:[EDI+14], 10C290
 	C747 18 90906068 MOV DWORD PTR DS:[EDI+18], 68609090
 	894F 1C MOV DWORD PTR DS:[EDI+1C], ECX
 	C747 20 909090B8 MOV DWORD PTR DS:[EDI+20], B8909090
 	894F 24 MOV DWORD PTR DS:[EDI+24], ECX
 	C747 28 90FFD061 MOV DWORD PTR DS:[EDI+28], 61D0FF90
 	C747 2C 90C20400 MOV DWORD PTR DS:[EDI+2C], 4C290
 	*/
 		$code1 = { 89 47 0C C7 47 10 90 C2 04 00 C7 47 14 90 C2 10 00 C7 47 18 90 90 60 68 89 4F 1C C7 47 20 90 90 90 B8 89 4F 24 C7 47 28 90 FF D0 61 C7 47 2C 90 C2 04 00}
 	/*
 	85C0 TEST EAX, EAX
 	75 25 JNZ SHORT 64106327.00403AF1
 	8B0B MOV ECX, DWORD PTR DS:[EBX]
 	BF ???????? MOV EDI, ????????
 	EB 17 JMP SHORT 64106327.00403AEC
 	69D7 0D661900 IMUL EDX, EDI, 19660D
 	8DBA 5FF36E3C LEA EDI, DWORD PTR DS:[EDX+3C6EF35F]
 	89FE MOV ESI, EDI
 	C1EE 10 SHR ESI, 10
 	89F2 MOV EDX, ESI
 	301401 XOR BYTE PTR DS:[ECX+EAX], DL
 	40 INC EAX
 	3B43 04 CMP EAX, DWORD PTR DS:[EBX+4]
 	72 E4 JB SHORT 64106327.00403AD5
 	*/
 		$code2 = { 85 C0 75 25 8B 0B BF ?? ?? ?? ?? EB 17 69 D7 0D 66 19 00 8D BA 5F F3 6E 3C 89 FE C1 EE 10 89 F2 30 14 01 40 3B 43 04 72 E4}
 		$code3 = {90 90 90 ?? B9 00 4D 5A 90 00 03 00 00 00 82 04}
		$code4 = {55 89 E5 5D C3 55 89 E5 83 EC 18 8B 45 08 85 C0}

 	condition:
 		$mz at 0 and (($code1 or $code2) or ($code3 and $code4))
}
