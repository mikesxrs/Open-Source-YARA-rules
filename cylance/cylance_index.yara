rule antivirusdetector
{
	meta:
		reference = "https://cdn2.hubspot.net/hubfs/270968/assets/Cleaver/Cylance_Operation_Cleaver_Report.pdf"

	strings:
		$s1 = "getShadyProcess"
		$s2 = "getSystemAntiviruses"
		$s3 = "AntiVirusDetector"
		
	condition:
		all of them
}

rule BackDoorLogger
{
	meta:
		reference = "https://cdn2.hubspot.net/hubfs/270968/assets/Cleaver/Cylance_Operation_Cleaver_Report.pdf"
		
 	strings:
 		$s1 = "BackDoorLogger"
 		$s2 = "zhuAddress"

 	condition:
 		all of them
}

rule csext
{
	meta:
		reference = "https://cdn2.hubspot.net/hubfs/270968/assets/Cleaver/Cylance_Operation_Cleaver_Report.pdf"

 	strings:
 		$s1 = "COM+ System Extentions"
 		$s2 = "csext.exe"
 		$s3 = "COM_Extentions_bin"
 	condition:
 		all of them
}

rule Misdat_Backdoor_Packed
{
	meta:
		author = "Cylance SPEAR Team"
		note = "Probably Prone to False Positive"

	strings:
		$upx = {33 2E 30 33 00 55 50 58 21}
		$send = {00 00 00 73 65 6E 64 00 00 00}
		$delphi_sec_pe = {50 45 00 00 4C 01 03 00 19 5E 42 2A}
		$shellexec = {00 00 00 53 68 65 6C 6C 45 78 65 63 75 74 65 57 00 00 00}
		
	condition:
		filesize < 100KB and $upx and $send and $delphi_sec_pe and $shellexec
}

rule MiSType_Backdoor_Packed
{
	meta:
		author = "Cylance SPEAR Team"
		note = "Probably Prone to False Positive"

	strings:
		$upx = {33 2E 30 33 00 55 50 58 21}
		$send_httpquery = {00 00 00 48 74 74 70 51 75 65 72 79 49 6E 66 6F 41 00 00 73 65 6E 64 00 00}
		$delphi_sec_pe = {50 45 00 00 4C 01 03 00 19 5E 42 2A}
	
	condition:
		filesize < 100KB and $upx and $send_httpquery and $delphi_sec_pe
}

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

rule Jasus
{
	meta:
		reference = "https://cdn2.hubspot.net/hubfs/270968/assets/Cleaver/Cylance_Operation_Cleaver_Report.pdf"

 	strings:
 		$s1 = "pcap_dump_open"
 		$s2 = "Resolving IPs to poison..."
 		$s3 = "WARNNING: Gateway IP can not be found"
 		
 	condition:
 		all of them
}

rule kagent
{
	meta:
		reference = "https://cdn2.hubspot.net/hubfs/270968/assets/Cleaver/Cylance_Operation_Cleaver_Report.pdf"

 	strings:
 		$s1 = "kill command is in last machine, going back"
 		$s2 = "message data length in B64: %d Bytes"
 		
 	condition:
 		all of them
}

rule LoggerModule
{
	meta:
		reference = "https://cdn2.hubspot.net/hubfs/270968/assets/Cleaver/Cylance_Operation_Cleaver_Report.pdf"

	strings:
		$s1 = "%s-%02d%02d%02d%02d%02d.r"
		$s2 = "C:\\Users\\%s\\AppData\\Cookies\\"

 	condition:
 		all of them
}

rule mimikatzWrapper
{
	meta:
		reference = "https://cdn2.hubspot.net/hubfs/270968/assets/Cleaver/Cylance_Operation_Cleaver_Report.pdf"

 	strings:
 		$s1 = "mimikatzWrapper"
 		$s2 = "get_mimikatz"
 		
 	condition:
 		all of them
}

rule NetC
{
	meta:
		reference = "https://cdn2.hubspot.net/hubfs/270968/assets/Cleaver/Cylance_Operation_Cleaver_Report.pdf"

	strings:
		$s1 = "NetC.exe" wide
		$s2 = "Net Service"
        
	condition:
		all of them
}

rule pvz_in
{
	meta:
		reference = "https://cdn2.hubspot.net/hubfs/270968/assets/Cleaver/Cylance_Operation_Cleaver_Report.pdf"

 	strings:
 		$s1 = "LAST_TIME=00/00/0000:00:00PM$"
 		$s2 = "if %%ERRORLEVEL%% == 1 GOTO line"
 		
 	condition:
 		all of them
}

rule pvz_out
{
	meta:
		reference = "https://cdn2.hubspot.net/hubfs/270968/assets/Cleaver/Cylance_Operation_Cleaver_Report.pdf"

	strings:
		$s1 = "Network Connectivity Module" wide
    	$s2 = "OSPPSVC" wide

	condition:
		all of them
}

rule ShellCreator2
{
	meta:
		reference = "https://cdn2.hubspot.net/hubfs/270968/assets/Cleaver/Cylance_Operation_Cleaver_Report.pdf"

	strings:
 		$s1 = "ShellCreator2.Properties"
 		$s2 = "set_IV"
 		
 	condition:
 		all of them
}

rule SmartCopy2
{
	meta:
		reference = "https://cdn2.hubspot.net/hubfs/270968/assets/Cleaver/Cylance_Operation_Cleaver_Report.pdf"

	strings:
	 $s1 = "SmartCopy2.Properties"
	 $s2 = "ZhuFrameWork"
	 
	condition:
	 all of them
}

rule SynFlooder
{
	meta:
		reference = "https://cdn2.hubspot.net/hubfs/270968/assets/Cleaver/Cylance_Operation_Cleaver_Report.pdf"

	strings:
    	$s1 = "Unable to resolve [ %s ]. ErrorCode %d"
    	$s2 = "your target's IP is : %s"
   		$s3 = "Raw TCP Socket Created successfully."
        
	condition:
    	all of them
}

rule TinyZBot
{

	meta:
		reference = "https://cdn2.hubspot.net/hubfs/270968/assets/Cleaver/Cylance_Operation_Cleaver_Report.pdf"

	strings:
    	$s1 = "NetScp" wide
    	$s2 = "TinyZBot.Properties.Resources.resources"
    	$s3 = "Aoao WaterMark"
    	$s4 = "Run_a_exe"
    	$s5 = "netscp.exe"
    	$s6 = "get_MainModule_WebReference_DefaultWS"
    	$s7 = "remove_CheckFileMD5Completed"
   		$s8 = "http://tempuri.org/"
    	$s9 = "Zhoupin_Cleaver"
    
	condition:
    	($s1 and $s2) or ($s3 and $s4 and $s5) or ($s6 and $s7 and $s8) or $s9
    }
    

rule wndTest
{
  meta:
	reference = "https://cdn2.hubspot.net/hubfs/270968/assets/Cleaver/Cylance_Operation_Cleaver_Report.pdf"

  strings:
    $s1 = "[Alt]" wide
    $s2 = "<< %s >>:" wide
    $s3 = "Content-Disposition: inline; comp=%s; account=%s; product=%d;"
  condition:
    all of them
}

rule zhCat
{
   meta:
	reference = "https://cdn2.hubspot.net/hubfs/270968/assets/Cleaver/Cylance_Operation_Cleaver_Report.pdf"

  strings:
    $s1 = "zhCat -l -h -tp 1234"
    $s2 = "ABC ( A Big Company )" wide
  condition:
    all of them
}

rule zhLookUp
{
  meta:
	reference = "https://cdn2.hubspot.net/hubfs/270968/assets/Cleaver/Cylance_Operation_Cleaver_Report.pdf"

  strings:
    $s1 = "zhLookUp.Properties"
    
  condition:
    all of them
}

rule zhmimikatz
{
  meta:
	reference = "https://cdn2.hubspot.net/hubfs/270968/assets/Cleaver/Cylance_Operation_Cleaver_Report.pdf"

  strings:
    $s1 = "MimikatzRunner"
    $s2 = "zhmimikatz"
  condition:
    all of them
}

rule ZhoupinExploitCrew
{
  meta:
	reference = "https://cdn2.hubspot.net/hubfs/270968/assets/Cleaver/Cylance_Operation_Cleaver_Report.pdf"

  strings:
    $s1 = "zhoupin exploit crew" nocase
    $s2 = "zhopin exploit crew" nocase
  condition:
    1 of them
}