rule Misdat_Backdoor
{
	meta:
		author = "Cylance SPEAR Team"
		/* Decode Function
		CODE:00406C71 8B 55 F4					mov     edx, [ebp+var_C]
		CODE:00406C74 8A 54 1A FF				mov     dl, [edx+ebx-1]
		CODE:00406C78 8B 4D F8					mov     ecx, [ebp+var_8]
		CODE:00406C7B C1 E9 08 					shr     ecx, 8
		CODE:00406C7E 32 D1						xor     dl, cl
		CODE:00406C80 88 54 18 FF				mov     [eax+ebx-1], dl
		CODE:00406C84 8B 45 F4					mov     eax, [ebp+var_C]
		CODE:00406C87 0F B6 44 18 FF			movzx   eax, byte ptr [eax+ebx-1]
		CODE:00406C8C 03 45 F8					add     eax, [ebp+var_8]
		CODE:00406C8F 69 C0 D9 DB 00 00  		imul    eax, 0DBD9h
		CODE:00406C95 05 3B DA 00 00 			add     eax, 0DA3Bh
		CODE:00406C9A 89 45 F8 					mov     [ebp+var_8], eax
		CODE:00406C9D 43 						inc     ebx
		CODE:00406C9E 4E 						dec     esi
		CODE:00406C9F 75 C9 					jnz     short loc_406C6A
		*/
	strings:
		$imul = {03 45 F8 69 C0 D9 DB 00 00 05 3B DA 00 00}
		$delphi = {50 45 00 00 4C 01 08 00 19 5E 42 2A}
		
	condition:
		$imul and $delphi
}