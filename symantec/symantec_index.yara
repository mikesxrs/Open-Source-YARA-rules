import "pe"

rule Bannerjack
{
 	meta:
 		author = "Symantec Security Response"
 		date = "2015-07-01"
 		description = "Butterfly BannerJack hacktool"
 		reference = "https://www.symantec.com/content/en/us/enterprise/media/security_response/whitepapers/butterfly-corporate-spies-out-for-financial-gain.pdf"
 	strings:
 		$str_1 = "Usage: ./banner-jack [options]"
 		$str_2 = "-f: file.csv"
 		$str_3 = "-s: ip start"
 		$str_4 = "-R: timeout read (optional, default %d secs)"
 	condition:
 		all of them
}

rule comrat
{
	meta:
		author = "Symantec"
		malware = "COMRAT"		
        Reference="https://www.symantec.com/content/en/us/enterprise/media/security_response/whitepapers/waterbug-attack-group.pdf"

	strings:
		$mz = "MZ"
		$b = {C645????}
		$c = {C685??FEFFFF??}
		//$d = {FFA0??0?0000}
		$e = {89A8??00000068??00000056FFD78B}
		$f = {00004889????030000488B}
	
	condition:
		($mz at 0) and ((#c > 200 and #b > 200 ) /*or (#d > 40)*/ and (#e > 15 or #f > 30))
}


rule Eventlog 
{ 
	meta: 
		author = "Symantec Security Response"
		date = "2015-07-01" 
		description = "Butterfly Eventlog hacktool"
 		reference = "https://www.symantec.com/content/en/us/enterprise/media/security_response/whitepapers/butterfly-corporate-spies-out-for-financial-gain.pdf"

	strings: 
		$str_1= "wevtsvc.dll"
		$str_2= "Stealing %S.evtx handle ..."
		$str_3= "ElfChnk"
		$str_4= "-Dr Dump all logs from a channel or .evtx file (raw"

	condition: 
		all of them 
}

rule fa
{
	meta:
 		author = "Symantec"
 		reference = "https://www.symantec.com/content/en/us/enterprise/media/security_response/whitepapers/waterbug-attack-group.pdf"

 	strings:
 		$mz = "MZ"
 		$string1 = "C:\\proj\\drivers\\fa _ 2009\\objfre\\i386\\atmarpd.pdb"

		$string2 = "d:\\proj\\cn\\fa64\\"
		$string3 = "sengoku _ Win32.sys\x00"
		$string4 = "rk _ ntsystem.c"
		$string5 = "\\uroboros\\"
		$string6 = "shell.{F21EDC09-85D3-4eb9-915F-1AFA2FF28153}"

	condition:
 		($mz at 0) and (any of ($string*))
}

rule Hacktool 
{ 
	meta: 
		author = "Symantec Security Response"
		date = "2015-07-01" 
		description = "Butterfly hacktool"
		reference = "https://www.symantec.com/content/en/us/enterprise/media/security_response/whitepapers/butterfly-corporate-spies-out-for-financial-gain.pdf"

	strings: 
		$str_1 = "\\\\.\\pipe\\winsession" wide 
		$str_2 = "WsiSvc" wide 
		$str_3 = "ConnectNamedPipe"
		$str_4 = "CreateNamedPipeW" 
		$str_5 = "CreateProcessAsUserW"
        
	condition: 
		all of them 
}

private rule isPE
{
	meta:
		Author = "Symantec"
		Reference = "https://www.symantec.com/content/en/us/enterprise/media/security_response/whitepapers/Dragonfly_Threat_Against_Western_Energy_Suppliers.pdf"

 	condition:
 		uint16(0) == 0x5A4D and uint32(uint32(0x3c)) == 0x00004550
}


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

rule Trojan_Karagany
{
	meta:
		alias = "Dreamloader"
		Author = "Symantec"
		Reference = "https://www.symantec.com/content/en/us/enterprise/media/security_response/whitepapers/Dragonfly_Threat_Against_Western_Energy_Suppliers.pdf"

	strings:
		$s1 = "neosphere" wide ascii
		$s2 = "10000000000051200" wide ascii
		$v1 = "&fichier" wide ascii
		$v2 = "&identifiant" wide ascii
		$c1 = "xmonstart" wide ascii
		$c2 = "xmonstop" wide ascii
		$c3 = "xgetfile" wide ascii
		$c4 = "downadminexec" wide ascii
		$c5 = "xdiex" wide ascii
		$c6 = "xrebootx" wide ascii

	condition:
		isPE and (($s1 and $s2) or ($v1 and $v2) or (any of ($c*)))
}


rule Multipurpose 
{ 
	meta: 
		author = "Symantec Security Response"
		date = "2015-07-01" 
		description = "Butterfly Multipurpose hacktool" 
		reference = "https://www.symantec.com/content/en/us/enterprise/media/security_response/whitepapers/butterfly-corporate-spies-out-for-financial-gain.pdf"
	strings: 
		$str_1 = "dump %d|%d|%d|%d|%d|%d|%s|%d"
		$str_2 = "kerberos%d.dll"
		$str_3 = "\\\\.\\pipe\\lsassp" 
		$str_4 = "pth <PID:USER:DOMAIN:NTLM>: change" 
	condition: 
		all of them 
}

rule Proxy
{ 
	meta: 
		author = "Symantec Security Response"
		date = "2015-07-01"
		description = "Butterfly proxy hacktool" 
		reference = "https://www.symantec.com/content/en/us/enterprise/media/security_response/whitepapers/butterfly-corporate-spies-out-for-financial-gain.pdf"

	strings: 
		$str_1 = "-u user : proxy username" 
		$str_2 = "--pleh : displays help" 
		$str_3 = "-x ip/host : proxy ip or host" 
		$str_4 = "-m : bypass mutex check"
        
	condition: 
		all of them 
}

rule sav_dropper
{
	meta:
 		author = "Symantec"
 		malware = "SAV dropper"
 		reference = "https://www.symantec.com/content/en/us/enterprise/media/security_response/whitepapers/waterbug-attack-group.pdf"
 	
    strings:
 		$mz = "MZ"
 		$a = /[a-z]{,10} _ x64.sys\x00hMZ\x00/
 	
    condition:
 		($mz at 0) and uint32(0x400) == 0x000000c3 and pe.number_of_sections == 6 and $a
}

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


rule Securetunnel 
	{ 
	meta: 
		author = "Symantec Security Response"
		date = "2015-07-01"
		description = "Butterfly Securetunnel hacktool"
		reference = "https://www.symantec.com/content/en/us/enterprise/media/security_response/whitepapers/butterfly-corporate-spies-out-for-financial-gain.pdf"

	strings: 
		$str_1 = "KRB5CCNAME" 
		$str_2 = "SSH _ AUTH _ SOCK" 
		$str_3 = "f:l:u:cehR" 
		$str_4 = ".o+=*BOX@%&#/^SE"

	condition: 
		all of them 
}

	
rule turla_dll
{
	
    meta:
 		Malware = "Trojan.Turla DLL"
 		author = "Symantec"
 		reference = "https://www.symantec.com/content/en/us/enterprise/media/security_response/whitepapers/waterbug-attack-group.pdf"
        
	strings:
		$a = /([A-Za-z0-9]{2,10} _ ){,2}Win32\.dll\x00/

	condition:
		pe.exports("ee") and $a
}


rule turla_dropper
{
	meta:
 		Malware = "Trojan.Turla dropper"
 		author = "Symantec"
 		reference = "https://www.symantec.com/content/en/us/enterprise/media/security_response/whitepapers/waterbug-attack-group.pdf"
 	
	strings:
		$a = {0F 31 14 31 20 31 3C 31 85 31 8C 31 A8 31 B1 31 D1 31 8B 32 91 32 B6 32 C4 32 6C 33 AC 33 10 34}
		$b = {48 41 4C 2E 64 6C 6C 00 6E 74 64 6C 6C 2E 64 6C 6C 00 00 00 57 8B F9 8B 0D ?? ?? ?? ?? ?? C9 75 26 56 0F 20 C6 8B C6 25 FF FF FE FF 0F 22 C0 E8}
        
	condition:
		all of them
}

rule wipbot_2013_core_PDF
{
	meta:
		author = "Symantec"
		description = "Trojan.Wipbot 2014 core PDF"
		reference = "https://www.symantec.com/content/en/us/enterprise/media/security_response/whitepapers/waterbug-attack-group.pdf"
 	strings:
 		$PDF = "%PDF-"
 		$a = /\+[A-Za-z]{1}\. _ _ \$\+[A-Za-z]{1}\. _ \$ _ \+/
 		$b = /\+[A-Za-z]{1}\.\$\$\$ _ \+/

 	condition:
 		($PDF at 0) and #a > 150 and #b > 200
}

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

rule remsec_executable_blob_32
{
meta:
copyright = "Symantec"
strings:
$code =
/*
31 06                       l0: xor     [esi], eax
83 C6 04                        add     esi, 4
D1 E8                           shr     eax, 1
73 05              
jnb     short l1
35 01 00 00 D0                  xor     eax, 0D0000001h
E2 F0                       l1: loop    l0
*/
{
31 06
83 C6 04
D1 E8
73 05
35 01 00 00 D0
E2 F0
}
condition:
all of them
}

rule remsec_executable_blob_64
{
meta:
copyright = "Symantec"
strings:
$code =
/*
31 06                       l0: xor   
[rsi], eax
48 83 C6 04                     add     rsi, 4
D1 E8                           shr     eax, 1
73 05                           jnb     short l1
35 01 00 00 D0                  xor     eax, 0D00000
01h
E2 EF                       l1: loop    l0
*/
{
31 06
48 83 C6 04
D1 E8
73 05
35 01 00 00 D0
E2 EF
}
condition:
all of them
}

rule 
remsec_executable_blob_parser
{
meta:
copyright = "Symantec"
strings:
$code =
/*
0F 82 ?? ?? 00 00               jb      l_0
80 7? 04 02                     cmp     byte ptr [r0+4], 2
0F 
85 ?? ?? 00 00               jnz     l_0
81 3? 02 AA 02 C1               cmp     dword ptr [r0], 
0C102AA02h
0F 85 ?? ?? 00 00               jnz     l_0
8B ?? 06                        mov     r1, [r0+6]
*/
{
( 0F 82 ?? ?? 00 00 | 72 ?? )
( 80 | 41 80 ) ( 7? | 7C 24 ) 04 02
( 0F 85 ?? ?? 00 00 | 75 ?? )
( 81 | 41 81 ) ( 3? | 3C 24 | 7D 00 ) 02 AA 02 C1
( 0F 85 ?? ?? 00 00 | 75 ?? )
( 8B | 41 
8B | 44 8B | 45 8B ) ( 4? | 5? | 6? | 7? | ?4 24 | 
?C 24 ) 06
}
condition:
all of them
}

rule remsec_encrypted_api
{
meta:
copyright = "Symantec"
strings:
$open_process =
/*
"OpenProcess
\
x00" in encrypted form
*/
{ 91 9A 8F B0 9C 90 8D AF 8C 8C 9A FF }
condition:
all of them
}

rule remsec_packer_A
{
meta:
copyright = "Symantec"
strings:
$code =
/*
69 ?? AB 00 00 00               imul    r0, 0ABh
81 C? CD 2B 00 00               add     r0, 2BCDh
F7 E?                           mul     r0
C1 E? 0D                        shr     r1, 0Dh
69 ?? 85 CF 00 00               imul    r1, 0CF85h
2B                              sub     r0, r1
*/
{
69 ( C? | D? | E? | F? ) AB 00 00 00
( 81 | 41 81 ) C? CD 2B 00 00
( F7 | 41 
F7 ) E?
( C1 | 41 C1 ) E? 0D
( 69 | 45 69 ) ( C? | D? | E? | F? ) 85 CF 00 00
( 29 | 41 29 | 44 29 | 45 29 | 2B | 41 2B | 44 2B | 45 2B )
}
condition:
all of them
}

rule remsec_packer_B
{
meta:
copyright = "Symantec"
strings:
$code =
/*
48 8B 05 C4 2D 01 00            mov     rax, cs:LoadLibraryA
48 89 44 24 48                  mov     qword ptr 
[rsp+1B8h+descriptor+18h], rax
48 8B 05 A
0 2D 01 00            mov     rax, cs:GetProcAddress
48 8D 4C 24 30                  lea     rcx, 
[rsp+1B8h+descriptor]
48 89 44 2
4 50                  mov     qword ptr 
[rsp+1B8h+descriptor+20h], rax
48 8D 84 24 80 00 00 00         lea     rax, 
[rsp+1B8h+var_138]
C6 44 24 30 00                  mov     [rsp+1B8h+descriptor], 
0
48 89 44 24 60      
mov     qword ptr 
[rsp+1B8h+descriptor+30h], rax
48 8D 84 24 80 00 00 00         lea     rax, 
[rsp+1B8h+var_138]
C7 44 24 34 03 00 00 00         mov     dword ptr 
[rsp+1B8h+descriptor+4], 3
2B F8             
sub     edi, eax
48 89 5C 24 38                  mov     qword ptr 
[rsp+1B8h+descriptor+8], rbx
44 89 6C 24 40                  mov     dword ptr 
[rsp+1B8h+descriptor+10h], r13d
83 C7 08                    
add     edi, 8
89 7C 24 68                     mov     dword ptr 
[rsp+1B8h+descriptor+38h], edi
FF D5                           call    rbp
05 00 00 00 3A                  add     eax, 3A000000h
*/
{
48 8B 05 ?? ?? ?? ??
48 89 44 24 ??
48 8B 05 ?? ?? ?? ??
48 8D 4C 24 ??
48 89 44 24 ??
48 8D ( 45 ?? | 84 24 ?? ?? 00 00 )
( 44 88 6? 24 ?? | C6 44 24 ?? 00 )
48 89 44 24 ??
48 8D ( 45 ?? | 84 24 ?? ?? 00 00 )
C7 44 24 ?? 0? 00 00 00
2B ?8
48 89 ?C 24 ??
44 89 6? 24 ??
83 C? 08
89 ?C 24 ??
( FF | 41 FF ) D?
( 05 | 8D 88 ) 00 00 00 3A
}
condition:
all of them
}

rule Cadelle_1
{
meta:
	author = "Symantec"
	reference = "http://www.symantec.com/content/en/us/enterprise/media/security_response/docs/CadelSpy-Remexi-IOC.pdf"
strings:
	$s1 = { 56 57 8B F8 8B F1 33 C0 3B F0 74 22 39 44 24 0C 74 18 0F B7 0F 66 3B C8 74 10 66 89 0A 42 42 47 47 4E FF 4C 24 0C 3B F0 75 E2 3B F0 75 07 4A 4A B8 7A 00 07 80 33 C9 5F 66 89 0A 5E C2 04 00}
	$s2 = "ntsvc32"
	$s3 = "ntbind32"
condition:
	$s1 and ($s2 or $s3)
}

rule Cadelle_2
{
meta:
	author = "Symantec"
	reference = "http://www.symantec.com/content/en/us/enterprise/media/security_response/docs/CadelSpy-Remexi-IOC.pdf"
strings:
	$s1  = "[EXECUTE]" wide ascii
	$s2  = "WebCamCapture" wide ascii
	$s3  = "</DAY>" wide ascii
	$s4  ="</DOCUMENT>" wide ascii
	$s5  = "<DOCUMENT>" wide ascii
	$s6  = "<DATETIME>" wide ascii
	$s7  = "Can't open file for reading :" wide ascii
	$s8  = "</DATETIME>" wide ascii
	$s9  = "</USERNAME>" wide ascii
	$s10 = "JpegFile :" wide ascii
	$s12 = "[SCROLL]" wide ascii
	$s13 = "<YEAR>" wide ascii
	$s14 = "CURRENT DATE" wide ascii
	$s15 = "</YEAR>" wide ascii
	$s16 = "</MONTH>" wide ascii
	$s17 = "<PRINTERNAME>" wide ascii
	$s18 = "</DRIVE>" wide ascii
	$s19 = "<DATATYPE>" wide ascii
	$s20 = "<MACADDRESS>" wide ascii
	$s21 = "FlashMemory" wide ascii
condition:
	12 of them
}

rule Cadelle_3
{
meta:
	author = "Symantec"
	reference = "http://www.symantec.com/content/en/us/enterprise/media/security_response/docs/CadelSpy-Remexi-IOC.pdf"
strings:
	$s1  = "SOFTWARE\\ntsvc32\\HDD" wide ascii
	$s2  = "SOFTWARE\\ntsvc32\\ROU" wide ascii
	$s3  = "SOFTWARE\\ntsvc32\\HST" wide ascii
	$s4  = "SOFTWARE\\ntsvc32\\FLS" wide ascii
	$s5  = "ntsvc32" wide ascii
	$s6  = ".Win$py." wide ascii
	$s7  = "C:\\users\\" wide ascii
	$s8  = "%system32%" wide ascii
	$s9  = "\\Local Settings\\Temp" wide ascii
	$s10 = "SVWATAUAVAW" wide ascii
	$s11 = "\\AppData\\Local" wide ascii
	$s12 = "\\AppData" wide ascii
condition:
	6 of them
}

rule Cadelle_4
{
meta:
	author = "Symantec"
	reference = "http://www.symantec.com/content/en/us/enterprise/media/security_response/docs/CadelSpy-Remexi-IOC.pdf"
strings:
	$s1 = "AppInit_DLLs" wide ascii
	$s2 = { 5C 00 62 00 61 00 63 00 6B 00 75 00 70 00 00 }
	$s3 = { 5C 00 75 00 70 00 64 00 61 00 74 00 65 00 00 }
	$s4 = "\\cmd.exe" wide ascii
condition:
	all of them
}
