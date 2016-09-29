rule sav{
	meta:
 		author = "Symantec"
 		malware = "SAV"
 		reference = "https://www.symantec.com/content/en/us/enterprise/media/security_response/whitepapers"

	strings:
		$mz = "MZ"
/*
8B 75 18 mov esi, [ebp+arg _ 10]
31 34 81 xor [ecx+eax*4], esi
40 inc eax
3B C2 cmp eax, edx
72 F5 jb short loc _ 9F342
33 F6 xor esi, esi
39 7D 14 cmp [ebp+arg _ C], edi
76 1B jbe short loc _ 9F36F
8A 04 0E mov al, [esi+ecx]
88 04 0F mov [edi+ecx], al
6A 0F push 0Fh
33 D2 xor edx, edx
8B C7 mov eax, edi
5B pop ebx
F7 F3 div ebx
85 D2 test edx, edx
75 01 jnz short loc _ 9F368
*/
	$code1a = { 8B 75 18 31 34 81 40 3B C2 72 F5 33 F6 39 7D 14 76 1B 8A 04 0E 88 04 0F 6A 0F 33 D2 8B C7 5B F7 F3 85 D2 75 01 }

/*
8B 45 F8 mov eax, [ebp+var _ 8]
40 inc eax
89 45 F8 mov [ebp+var _ 8], eax
8B 45 10 mov eax, [ebp+arg _ 8]
C1 E8 02 shr eax, 2
39 45 F8 cmp [ebp+var _ 8], eax
73 17 jnb short loc _ 4013ED
8B 45 F8 mov eax, [ebp+var _ 8]
8B 4D F4 mov ecx, [ebp+var _ C]
8B 04 81 mov eax, [ecx+eax*4]
33 45 20 xor eax, [ebp+arg _ 18]
8B 4D F8 mov ecx, [ebp+var _ 8]
8B 55 F4 mov edx, [ebp+var _ C]
89 04 8A mov [edx+ecx*4], eax
EB D7 jmp short loc _ 4013C4
83 65 F8 00 and [ebp+var _ 8], 0
83 65 EC 00 and [ebp+var _ 14], 0
EB 0E jmp short loc _ 401405
8B 45 F8 mov eax, [ebp+var _ 8]
40 inc eax
89 45 F8 mov [ebp+var _ 8], eax
8B 45 EC mov eax, [ebp+var _ 14]
40 inc eax
89 45 EC mov [ebp+var _ 14], eax
8B 45 EC mov eax, [ebp+var _ 14]
3B 45 10 cmp eax, [ebp+arg _ 8]
73 27 jnb short loc _ 401434
8B 45 F4 mov eax, [ebp+var _ C]
03 45 F8 add eax, [ebp+var _ 8]
8B 4D F4 mov ecx, [ebp+var _ C]
03 4D EC add ecx, [ebp+var _ 14]
8A 09 mov cl, [ecx]
88 08 mov [eax], cl
8B 45 F8 mov eax, [ebp+var _ 8]
33 D2 xor edx, edx
6A 0F push 0Fh
59 pop ecx
F7 F1 div ecx
85 D2 test edx, edx
75 07 jnz short loc _ 401432
*/

	$code1b = { 8B 45 F8 40 89 45 F8 8B 45 10 C1 E8 02 39 45 F8 73 17 8B 45 F8 8B 4D F4 8B 04 81 33 45 20 8B 4D F8 8B 55 F4 89 04 8A EB D7 83 65 F8 00 83 65 EC 00 EB 0E 8B 45 F8 40 89 45 F8 8B 45 EC 40 89 45 EC 8B 45 EC 3B 45 10 73 27 8B 45 F4 03 45 F8 8B 4D F4 03 4D EC 8A 09 88 08 8B 45 F8 33 D2 6A 0F 59 F7 F1 85 D2 75 07 }

/*
8A 04 0F mov al, [edi+ecx]
88 04 0E mov [esi+ecx], al
6A 0F push 0Fh
33 D2 xor edx, edx
8B C6 mov eax, esi
5B pop ebx
F7 F3 div ebx
85 D2 test edx, edx
75 01 jnz short loc _ B12FC
47 inc edi
8B 45 14 mov eax, [ebp+arg _ C]
46 inc esi
47 inc edi
3B F8 cmp edi, eax
72 E3 jb short loc _ B12E8
EB 04 jmp short loc _ B130B
C6 04 08 00 mov byte ptr [eax+ecx], 0
48 dec eax
3B C6 cmp eax, esi
73 F7 jnb short loc _ B1307
33 C0 xor eax, eax
C1 EE 02 shr esi, 2
74 0B jz short loc _ B1322
8B 55 18 mov edx, [ebp+arg _ 10]
31 14 81 xor [ecx+eax*4], edx
40 inc eax
3B C6 cmp eax, esi
72 F5 jb short loc _ B1317
*/

		$code1c = { 8A 04 0F 88 04 0E 6A 0F 33 D2 8B C6 5B F7 F3 85 D2 75 01 47 8B 45 14 46 47 3B F8 72 E3 EB 04 C6 04 08 00 48 3B C6 73 F7 33 C0 C1 EE 02 74 0B 8B 55 18 31 14 81 40 3B C6 72 F5}

/*
29 5D 0C sub [ebp+arg _ 4], ebx
8B D1 mov edx, ecx
C1 EA 05 shr edx, 5
2B CA sub ecx, edx
8B 55 F4 mov edx, [ebp+var _ C]
2B C3 sub eax, ebx
3D 00 00 00 01 cmp eax, 1000000h
89 0F mov [edi], ecx
8B 4D 10 mov ecx, [ebp+arg _ 8]
8D 94 91 00 03 00 00 lea edx, [ecx+edx*4+300h]
73 17 jnb short loc _ 9FC44
8B 7D F8 mov edi, [ebp+var _ 8]
8B 4D 0C mov ecx, [ebp+arg _ 4]
0F B6 3F movzx edi, byte ptr [edi]
C1 E1 08 shl ecx, 8
0B CF or ecx, edi
C1 E0 08 shl eax, 8
FF 45 F8 inc [ebp+var _ 8]
89 4D 0C mov [ebp+arg _ 4], ecx
8B 0A mov ecx, [edx]
8B F8 mov edi, eax
C1 EF 0B shr edi, 0Bh
*/

		$code2 = { 29 5D 0C 8B D1 C1 EA 05 2B CA 8B 55 F4 2B C3 3D 00 00 00 01 89 0F 8B 4D 10 8D 94 91 00 03 00 00 73 17 8B 7D F8 8B 4D 0C 0F B6 3F C1 E1 08 0B CF C1 E0 08 FF 45 F8 89 4D 0C 8B 0A 8B F8 C1 EF 0B}

	condition:
		($mz at 0) and (($code1a or $code1b or $code1c) and $code2)
}