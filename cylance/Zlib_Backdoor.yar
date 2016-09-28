rule Zlib_Backdoor
{
	meta:
		author = "Cylance SPEAR Team"
		
		/* String
		C7 45 FC 00 04 00 00    	  mov     [ebp+Memory], 400h
		C6 45 D8 50                   mov     [ebp+Str], 'P'
		C6 45 D9 72                   mov     [ebp+var_27], 'r'
		C6 45 DA 6F                   mov     [ebp+var_26], 'o'
		C6 45 DB 78                   mov     [ebp+var_25], 'x'
		C6 45 DC 79                   mov     [ebp+var_24], 'y'
		C6 45 DD 2D                   mov     [ebp+var_23], '-'
		C6 45 DE 41                   mov     [ebp+var_22], 'A'
		C6 45 DF 75                   mov     [ebp+var_21], 'u'
		C6 45 E0 74                   mov     [ebp+var_20], 't'
		C6 45 E1 68                   mov     [ebp+var_1F], 'h'
		C6 45 E2 65                   mov     [ebp+var_1E], 'e'
		C6 45 E3 6E                   mov     [ebp+var_1D], 'n'
		C6 45 E4 74                   mov     [ebp+var_1C], 't'
		C6 45 E5 69                   mov     [ebp+var_1B], 'i'
		C6 45 E6 63                   mov     [ebp+var_1A], 'c'
		C6 45 E7 61                   mov     [ebp+var_19], 'a'
		C6 45 E8 74                   mov     [ebp+var_18], 't'
		C6 45 E9 65                   mov     [ebp+var_17], 'e'
		C6 45 EA 3A                   mov     [ebp+var_16], ':'
		C6 45 EB 20                   mov     [ebp+var_15], ' '
		C6 45 EC 4E                   mov     [ebp+var_14], 'N'
		C6 45 ED 54                   mov     [ebp+var_13], 'T'
		C6 45 EE 4C                   mov     [ebp+var_12], 'L'
		C6 45 EF 4D                   mov     [ebp+var_11], 'M'
		C6 45 F0 20                   mov     [ebp+var_10], ' '
		*/


	strings:
    $auth = {C6 45 D8 50 C6 45 D9 72 C6 45 DA 6F C6 45 DB 78 C6 45 DC 79 C6 45 DD 2D}
    $auth2 = {C7 45 FC 00 04 00 00 C6 45 ?? 50 C6 45 ?? 72 C6 45 ?? 6F}
		$ntlm = "NTLM" wide
	
	condition:
		($auth or $auth2) and $ntlm
}