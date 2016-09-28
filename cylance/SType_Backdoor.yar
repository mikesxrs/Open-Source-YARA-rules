rule SType_Backdoor
{
	meta:
		author = "Cylance SPEAR Team"
		
		/* Decode Function
		8B 1A		mov     ebx, [edx]
		8A 1B		mov     bl, [ebx]
		80 EB 02	sub     bl, 2
		8B 74 24 08 mov     esi, [esp+14h+var_C]
		32 1E		xor     bl, [esi]
		8B 31		mov     esi, [ecx]
		88 1E		mov     [esi], bl
		8B 1A		mov     ebx, [edx]
		43			inc     ebx
		89 1A		mov     [edx], ebx
		8B 19		mov     ebx, [ecx]
		43			inc     ebx
		89 19		mov     [ecx], ebx
		48			dec     eax
		75 E2		jnz     short loc_40EAC6
		*/

	strings:
		$stype = "stype=info&data="
		$mmid = "?mmid="
		$status = "&status=run succeed"
		$mutex = "_KB10B2D1_CIlFD2C"
		$decode = {8B 1A 8A 1B 80 EB 02 8B 74 24 08 32 1E 8B 31 88 1E 8B 1A 43}
	
	condition:
		$stype or ($mmid and $status) or $mutex or $decode
}