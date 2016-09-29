// From CERT report https://www.us-cert.gov/ncas/alerts/TA14-353A
rule SMB_Worm_Tool
{
	
	strings:	
		$STR1 = "Global\\FwtSqmSession106829323_S-1-5-19"
		$STR2 = "EVERYONE"
		$STR3 = "y0uar3@s!llyid!07,ou74n60u7f001"
		$STR4 = "\\KB25468.dat" 
	
	condition:
		( uint16(0) == 0x5A4D or 
		  uint16(0) == 0xCFD0 or 
		  uint16(0) == 0xC3D4 or 
		  uint32(0) == 0x46445025 or 
		  uint32(1) == 0x6674725C) 
		and all of them
}

rule Lightweight_Backdoor1
{

	strings:
		$STR1 = "NetMgStart"
		$STR2 = "Netmgmt.srg"
		
	condition:
		(uint16(0) == 0x5A4D) and all of them
}
rule LightweightBackdoor2
{
	strings:
		$STR1 = "prxTroy" ascii wide nocase
	
	condition:
		(uint16(0) == 0x5A4D or uint16(0) == 0xCFD0 or uint16(0) == 0xC3D4 or uint32(0) == 0x46445025 or uint32(1) == 0x6674725C) and all of them
}
rule LightweightBackdoor3
{
	
	strings:
		$strl  = { C6 45 E8 64 C6 45 E9 61 C6 45 EA 79 C6 45 EB 69 C6 45 EC 70 C6 45 ED 6D C6 45 EE 72 C6 45 EF 2E C6 45 F0 74 C6 45 F1  62 C6 45 F2 6C } // 'dayipmr.tbl' being moved to ebp
	
	condition:
		(uint16(0) == 0x5A4D or uint16(0) == 0xCFD0 or uint16(0) == 0xC3D4 or uint32(0) == 0x46445025 or uint32(1) == 0x6674725C) and all of them
}
rule LightweightBackdoor4
{
	strings:	
		$strl  = { C6 45 F4 61 C6 45 F5 6E C6 45 F6 73 C6 45 F7 69 C6 45 F8 2E C6 45 F9 6E C6 45 FA 6C C6 45 FB 73 } // 'ansi.nls' being moved to ebp
	
	condition:
		(uint16(0) == 0x5A4D or uint16(0) == 0xCFD0 or uint16(0) == 0xC3D4 or uint32(0) == 0x46445025 or uint32(1) == 0x6674725C) and all of them
}
 

rule LightweightBackdoor5
{
	strings:
		$strl  = { C6 45 F4 74 C6 45 F5 6C C6 45 F6 76 C6 45 F7 63 C6 45 F8 2E C6 45 F9 6E C6 45 FA 6C C6 45 FB 73 } // 'tlvc.nls' being moved to ebp
	
	condition:
		(uint16(0) == 0x5A4D or uint16(0) == 0xCFD0 or uint16(0) == 0xC3D4 or uint32(0) == 0x46445025 or uint32(1) == 0x6674725C) and all of them
}
 rule LightweightBackdoor6
{
	strings:
		$STR1 = { 8A 10 80 ?? 4E 80 ?? 79 88 10}
		$STR2 = { 8A 10 80?? 79 80 ?? 4E 88 10}
	
	condition:
		(uint16(0) == 0x5A4D or uint16(0) == 0xCFD0 or uint16(0) == 0xC3D4 or uint32(0) == 0x46445025 or uint32(1) == 0x6674725C) and all of them
}
 

rule ProxyTool1
{
	strings:
		$STR1 = "pmsconfig.msi" wide
		$STR2 = "pmslog.msi" wide
	
	condition:
		(uint16(0) == 0x5A4D or uint16(0) == 0xCFD0 or uint16(0) == 0xC3D4 or uint32(0) == 0x46445025 or uint32(1) == 0x6674725C) and any of them
}
rule ProxyTool2
{
strings:
	$STR1 = { 82 F4 DE D4 D3 C2 CA F5 C8 C8 D3 82 FB F4 DE D4 D3 C2 CA 94 95 FB D4 D1 C4 CF C8 D4 D3 89 C2 DF C2 87 8A CC 87 00 } // '%SystemRoot%\System32\svchost.exe -k' xor A7

condition:
	(uint16(0) == 0x5A4D or uint16(0) == 0xCFD0 or uint16(0) == 0xC3D4 or uint32(0) == 0x46445025 or uint32(1) == 0x6674725C) and all of them
}
 

rule ProxyTool3
{
	strings:
		$STR2 = {8A 04 17 8B FB 34 A7 46 88 02 83 C9 FF}
	
	condition:
		(uint16(0) == 0x5A4D or uint16(0) == 0xCFD0 or uint16(0) == 0xC3D4 or uint32(0) == 0x46445025 or uint32(1) == 0x6674725C) and $STR2
}
 
rule DestructiveHardDriveTool1
{
	strings:
		$str0= "MZ"
		$str1 = {c6 84 24 ?? ( 00 | 01 ) 00 00 }
		$xorInLoop = { 83 EC 20 B9 08 00 00 00 33 D2 56 8B 74 24 30 57 8D 7C 24 08 F3 A5 8B 7C 24 30 85 FF 7E 3A 8B 74 24 2C 8A 44 24 08 53 8A 4C 24 21 8A 5C 24 2B 32 C1 8A 0C 32 32 C3 32 C8 88 0C 32 B9 1E 00 00 00 8A 5C 0C 0C 88 5C 0C 0D 49 83 F9 FF 7F F2 42 88 44 24 0C 3B D7 7C D0 5B 5F 5E 83 C4 20 C3 }
	
	condition:
		$str0 at 0 and $xorInLoop and #str1 > 300
}

/*
rule DestructiveTargetCleaningTool1
{
	strings:
		$s1  = {d3000000 [4] 2c000000 [12] 95000000 [4] 6a000000 [8] 07000000}
	
	condition:
		(uint16(0) == 0x5A4D and uint16(uint32(0x3c)) == 0x4550) and all of them
}
*/

/*
rule DestructiveTargetCleaningTool2
{
	strings:
		$secureWipe = { 83 EC 34 53 55 8B 6C 24 40 56 57 83 CE FF 55 C7 44 24 2C D3 00 00 00 C7 44 24 30 2C 00 00 00 89 74 24 34 89 74 24 
								    38 C7 44 24 3C 95 00 00 00 C7 44 24 40 6A 00 00 00 89 74 24 44 C7 44 24 14 07 00 00 00 FF 15 ?? ?? ?? ?? 3B C6 89 
								    44 24 1C 0F 84 (D8 | d9) 01 00 00 33 FF 68 00 00 01 00 57 FF 15 ?? ?? ?? ?? 8B D8 3B DF 89 5C 24 14 0F 84 (BC | BD) 
									  01 00 00 8B 44 24 1C A8 01 74 0A 24 FE 50 55 FF 15 ?? ?? ?? ?? 8B 44 24 4C 2B C7 74 20 48 74 0F 83 E8 02 75 1C C7 
									  44 24 10 03 00 00 00 EB 12 C7 44 24 10 01 00 00 00 89 74 24 28 EB 04 89 7C 24 10 8B 44 24 10 89 7C 24 1C 3B C7 0F 
									  8E ( 5C | 5d ) 01 00 00 8D 44 24 28 89 44 24 4C EB 03 83 CE FF 8B 4C 24 4C 8B 01 3B C6 74 17 8A D0 B9 00 40 00 00 
									  8A F2 8B FB 8B C2 C1 E0 10 66 8B C2 F3 AB EB ( 13 | 14) 33 F6 (E8 | ff 15) ?? ?? ?? ?? 88 04 1E 46 81 FE 00 00 01 
									  00 7C ( EF | ee) 6A 00 6A 00 6A 03 6A 00 6A 03 68 00 00 00 C0 55 FF 15 ?? ?? ?? ?? 8B F0 83 FE FF 0F 84 FA 00 00 00 
									  8D 44 24 20 50 56 FF 15 ?? ?? ?? ?? 8B 2D ?? ?? ?? ?? 6A 02 6A 00 6A FF 56 FF D5 8D 4C 24 18 6A 00 51 6A 01 53 56 
			 					    FF 15 ?? ?? ?? ?? 56 FF 15 ?? ?? ?? ?? 6A 00 6A 00 6A 00 56 FF D5 8B 44 24 24 8B 54 24 20 33 FF 33 DB 85 C0 7C 5A 
									  7F 0A 85 D2 76 54 EB 04 8B 54 24 20 8B CA BD 00 00 01 00 2B CF 1B C3 85 C0 7F 0A 7C 04 3B CD 73 04 2B D7 8B EA 8B 
									  44 24 14 8D 54 24 18 6A 00 52 55 50 56 FF 15 ?? ?? ?? ?? 8B 6C 24 18 8B 44 24 24 03 FD 83 D3 00 3B D8 7C BE 7F 08 
									  8B 54 24 20 3B FA 72 B8 8B 2D ?? ?? ?? ?? 8B 5C 24 10 8B 7C 24 1C 8D 4B FF 3B F9 75 17 56 FF 15 ?? ?? ?? ?? 6A 00 
									  6A 00 6A 00 56 FF D5 56 FF 15 ?? ?? ?? ?? 56 FF 15 ?? ?? ?? ?? 56 FF 15 ?? ?? ?? ?? 8B 4C 24 4C 8B 6C 24 48 47 83 
									  C1 04 3B FB 8B 5C 24 14 89 7C 24 1C 89 4C 24 4C 0F 8C ( AE | AD) FE FF FF 6A 00 55 E8 ?? ?? ?? ?? 83 C4 08 53 FF 
									  15 ?? ?? ?? ?? 5F 5E 5D 5B 83 C4 34 C3 }
	
	condition:
		$secureWipe
}
*/

rule DestructiveTargetCleaningTool3
{
	
	strings:
		$S1_CMD_Arg = "/install" fullword
		$S2_CMD_Parse= "\"%s\"  /install \"%s\"" fullword
		$S3_CMD_Builder= "\"%s\"  \"%s\" \"%s\" %s" fullword
	
	condition:
		all of them
}
 

rule DestructiveTargetCleaningTool4
{

	strings:
		$BATCH_SCRIPT_LN1_0 = "goto x" fullword
		$BATCH_SCRIPT_LN1_1 = "del" fullword
		$BATCH_SCRIPT_LN2_0 = "if exist" fullword
		$BATCH_SCRIPT_LN3_0 = ":x" fullword
		$BATCH_SCRIPT_LN4_0 = "zz%d.bat" fullword
	
	condition:
		(#BATCH_SCRIPT_LN1_1 == 2) and all of them
}
rule DestructiveTargetCleaningTool5
{
	strings:
		$MCU_DLL_ZLIB_COMPRESSED2 = { 5C EC AB AE 81 3C C9 BC D5 A5 42 F4 54 91 04 28 34 34 79 80 6F 71 D5 52 1E 2A 0D }
	
	condition:
		$MCU_DLL_ZLIB_COMPRESSED2
}
 

rule DestructiveTargetCleaningTool6
{
	strings:
		$MCU_INF_StartHexDec = {010346080A30D63633000B6263750A5052322A00103D1B570A30E67F2A00130952690A503A0D2A000E00A26E15104556766572636C7669642E657865}
		$MCU_INF_StartHexEnc = {6C3272386958BF075230780A0A54676166024968790C7A6779588F5E47312739310163615B3D59686721CF5F2120263E1F5413531F1E004543544C55}
	
	condition:
		$MCU_INF_StartHexEnc or $MCU_INF_StartHexDec
}
 

rule DestructiveTargetCleaningTool7
{
	strings:
		$a = "SetFilePointer"
		$b = "SetEndOfFile"
		$c = {75 17 56 ff 15 ?? ?? ?? ?? 6a 00 6a 00 6a 00 56 ff D5 56 ff 15 ?? ?? ?? ?? 56}
	
	condition:
		(uint16(0) == 0x5A4D and uint16(uint32(0x3c)) == 0x4550) and all of them
}
 
rule DestructiveTargetCleaningTool8
{
	strings:
		$license = {E903FFFF820050006F007200740069006F006E007300200063006F007000790072006900670068007400200052006F006200650072007400200064006500200042006100740068002C0020004A006F007200690073002000760061006E002000520061006E007400770069006A006B002C002000440065006C00690061006E000000000000000250000000000A002200CE000800EA03FFFF8200}
		$PuTTY= {50007500540054005900}
	
	condition:
		(uint16(0) == 0x5A4D and uint16(uint32(0x3c)) == 0x4550) and $license and not $PuTTY
}

rule Malwareusedbycyberthreatactor1
{
	strings:
		// vvv---- this sig hits on a legit CRT function it seems. 
		$heapCreateFunction_0 = {33C06A003944240868001000000F94C050FF15????????85C0A3???????07436E893FEFFFF83F803A3???????0750D68F8030000E8??00000059EB0A83F8027518E8????000085C0750FFF35???????0FF15???????033C0C36A0158C3}
		
		$heapCreateFunction = { 55 8B EC B8 2C 12 00 00 E8 ?? ?? FF FF 8D 85 68 FF FF FF 53 50 C7 85 68 FF FF FF 94 00 00 00 FF 1? ?? ?? ?? ?0 85 C0 74 1A 83 BD 78 FF FF FF 02 75 11 83 BD 6C FF FF FF 05 72 08 6A 01 58 E9 02 01 00 00 8D 85 D4 ED FF F6 89 01 00 00 05 06 8? ?? ?? ?? 0F F1 5? ?? ?? ?? 08 5C 00 F8 4D 00 00 00 03 3D B8 D8 DD 4E DF FF F3 89 DD DF FF F7 41 38 A0 13 C6 17 C0 83 C7 A7 F0 42 C2 08 80 14 13 81 97 5E D8 D8 5D 4E DF FF F6 A1 65 06 8? ?? ?? ?? 0E 8? ?? ?0 00 08 3C 40 C8 5C 07 50 88 D8 5D 4E DF FF FE B4 98 D8 56 4F EF FF F6 80 40 10 00 05 05 3F F1 5? ?? ?? ?? 03 89 D6 4F EF FF F8 D8 D6 4F EF FF F7 41 38 A0 13 C6 17 C0 83 C7 A7 F0 42 C2 08 80 14 13 81 97 5E D8 D8 56 4F EF FF F5 08 D8 5D 4E DF FF F5 0E 8? ?? ?? ?? ?5 95 93 BC 37 43 E6 A2 C5 0E 8? ?? ?? ?? ?5 93 BC 35 97 43 04 08 BC 83 81 87 40 E8 03 93 B7 50 48 81 9E B0 14 13 81 97 5F 26 A0 A5 35 0E 8? ?? ?0 00 08 3C 40 C8 3F 80 27 41 D8 3F 80 37 41 88 3F 80 17 41 38 D4 5F C5 0E 89 8F EF FF F8 07 DF C0 65 91 BC 08 3C 00 35 BC 9C}
		
  	// vvv---- this sig hits on a legit CRT function it seems. 
		$getMajorMinorLinker = {568B7424086A00832600FF15???????06681384D5A75148B483C85C9740D03C18A481A880E8A401B8846015EC3}

		$openServiceManager = {FF15???0?0?08B?885??74????????????????5?FF15???0?0?08B?????0?0?08BF?85F?74}
	
	condition:
	
		all of them
}

rule Malwareusedbycyberthreatactor2
{
	strings:
		$str1 = "_quit"
		$str2 = "_exe"
		$str3 = "_put"
		$str4 = "_got"
		$str5 = "_get"
		$str6 ="_del"
		$str7 = "_dir"
		$str8 = { C7 44 24 18 1F F7}
	
	condition:
		(uint16(0) == 0x5A4D or uint16(0) == 0xCFD0  or uint16(0) == 0xC3D4 or uint32(0) == 0x46445025 or uint32(1) == 0x6674725C) and all of them
}
 
rule Malwareusedbycyberthreatactor3
{
	strings:
		$STR1 = { 50 68 80 00 00 00 68 FF FF 00 00 51 C7 44 24 1C 3a 8b 00 00 }
	
	condition:
		(uint16(0) == 0x5A4D or uint16(0) == 0xCFD0 or uint16(0) == 0xC3D4 or uint32(0) == 0x46445025 or uint32(1) == 0x6674725C) and all of them
}

import "pe"

rule DeltaCharlie
{
	meta:
		copyright = "2015 Novetta Solutions"
		author = "Novetta Threat Research & Interdiction Group - trig@novetta.com"

	strings:
		$rsaKey = {7B 4E 1E A7 E9 3F 36 4C DE F4 F0 99 C4 D9 B7 94 
		           A1 FF F2 97 D3 91 13 9D C0 12 02 E4 4C BB 6C 77 
		           48 EE 6F 4B 9B 53 60 98 45 A5 28 65 8A 0B F8 39 
		           73 D7 1A 44 13 B3 6A BB 61 44 AF 31 47 E7 87 C2 
		           AE 7A A7 2C 3A D9 5C 2E 42 1A A6 78 FE 2C AD ED 
		           39 3F FA D0 AD 3D D9 C5 3D 28 EF 3D 67 B1 E0 68 
		           3F 58 A0 19 27 CC 27 C9 E8 D8 1E 7E EE 91 DD 13 
		           B3 47 EF 57 1A CA FF 9A 60 E0 64 08 AA E2 92 D0}
		           
	condition:
		any of them
}

rule Derusbi_Server
{
	meta:
		Author = "Novetta"
		Reference = "http://www.novetta.com/wp-content/uploads/2014/11/Derusbi.pdf"

	strings:
		$uuid = "{93144EB0-8E3E-4591-B307-8EEBFE7DB28F}" wide ascii
		$infectionID1 = "-%s-%03d"
		$infectionID2 = "-%03d"
		$other = "ZwLoadDriver"

	condition:
		$uuid or ($infectionID1 and $infectionID2 and $other)
}

// yara rules that can cross boundaries between the various sets/types... more general detection signatures
import "pe"

rule wiper_unique_strings
{
	meta:
		copyright = "2015 Novetta Solutions"
		author = "Novetta Threat Research & Interdiction Group - trig@novetta.com"
	 	company = "novetta"

	 strings:
	 	$a = "C!@I#%VJSIEOTQWPVz034vuA"
		$b = "BAISEO%$2fas9vQsfvx%$"
		$c = "1.2.7.f-hanba-win64-v1"
		$d = "md %s&copy %s\\*.* %s"
		$e = "%sd.e%sc n%ssh%srewa%s ad%s po%sop%sing T%s %d \"%s\""
		$f = "Ge.tVol. .umeIn..for  mati.onW"
	
	condition:
		$a or $b or $c or $d or $e or $f
}


rule wiper_encoded_strings
{
	meta:
		copyright = "2015 Novetta Solutions"
		author = "Novetta Threat Research & Interdiction Group - trig@novetta.com"
 		company = "novetta"

	 strings:
	 	$scr = {89 D4 C4 D5 00 00 00}
	 	$explorer = {E2 DF D7 CB C8 D5 C2 D5 89 C2 DF C2 00 00 00 }
	 	$kernel32 = {CC C2 D5 C9 C2 CB 94 95  89 C3 CB CB 00 00 }

	condition:
		$scr or $explorer or $kernel32 
}


rule createP2P
{
	meta:
		copyright = "2015 Novetta Solutions"
		author = "Novetta Threat Research & Interdiction Group - trig@novetta.com"

	strings:
		$ = "CreatP2P Thread" wide

	condition:
		any of them
}

rule firewallOpener
{
	meta:
		copyright = "2015 Novetta Solutions"
		author = "Novetta Threat Research & Interdiction Group - trig@novetta.com"

	strings:
	 $ = "%sd.e%sc n%ssh%srewa%s ad%s po%sop%sing T%s %d \"%s\""
	 
	condition:
		any of them
		
}

rule hidkit
{
	meta:
		Author = "Novetta"
		Reference = "https://www.novetta.com/wp-content/uploads/2014/11/HiKit.pdf"

	strings:
		$a = "---HIDE"
		$b = "hide---port = %d"

	condition:
		uint16(0)==0x5A4D and uint32(uint32(0x3c))==0x00004550 and $a and $b
}

rule hikit
{
	meta:
		Author = "Novetta"
		Reference = "https://www.novetta.com/wp-content/uploads/2014/11/HiKit.pdf"

	strings:
		$hikit_pdb1 = /(H|h)ikit_/
		$hikit_pdb2 = "hikit\\"
		$hikit_str3 = "hikit>" wide

		$driver = "w7fw.sys" wide
		$device = "\\Device\\w7fw" wide
		$global = "Global\\%s__HIDE__" wide nocase
		$backdr = "backdoor closed" wide
		$hidden = "*****Hidden:" wide

	condition:
		(1 of ($hikit_pdb1,$hikit_pdb2,$hikit_str3)) and ($driver or $device or $global or $backdr or $hidden)
}



rule hikit2
{
	meta:
		Author = "Novetta"
		Reference = "https://www.novetta.com/wp-content/uploads/2014/11/HiKit.pdf"

	strings:
		$magic1 = {8C 24 24 43 2B 2B 22 13 13 13 00}
		$magic2 = {8A 25 25 42 28 28 20 1C 1C 1C 15 15 15 0E 0E 0E 05 05 05 00}

	condition:
		$magic1 and $magic2
}

import "pe"

rule HotelAlfa
{
	meta:
		copyright = "2015 Novetta Solutions"
		author = "Novetta Threat Research & Interdiction Group - trig@novetta.com"
		Source = "58dab205ecb1e0972027eb92f68cec6d208e5ab5.ex_"

	strings:
	
	$resourceHTML = "RSRC_HTML"
	/*
		8A 0C 18  mov     cl, [eax+ebx]
		80 F1 63  xor     cl, 63h
		88 0C 18  mov     [eax+ebx], cl
		8B 4D 00  mov     ecx, [ebp+0]
		40        inc     eax
		3B C1     cmp     eax, ecx
		72 EF     jb      short loc_4010B4
	*/

	$rscsDecoderLoop = {
			8A [2] 
			80 F1 ?? 
			88 [2] 
			8B [2] 
			40 
			3B ??
			72 EF 
		}

	condition:
		$resourceHTML and $rscsDecoderLoop in ((pe.sections[pe.section_index(".text")].raw_data_offset)..(pe.sections[pe.section_index(".text")].raw_data_offset + pe.sections[pe.section_index(".text")].raw_data_size))
}

rule IndiaAlfa_One
{
	meta:
		copyright = "2015 Novetta Solutions"
		author = "Novetta Threat Research & Interdiction Group - trig@novetta.com"

	strings:
		$ = "HwpFilePathCheck.dll"
		$ = "AdobeArm.exe"
		$ = "OpenDocument"
		
	condition:
		2 of them

}

rule IndiaAlfa_Two
{
	meta:
		copyright = "2015 Novetta Solutions"
		author = "Novetta Threat Research & Interdiction Group - trig@novetta.com"

	strings:
		$ = "ExePath: %s\nXlsPath: %s\nTmpPath: %s\n"
		
	condition:
		any of them

}

import "pe"

rule IndiaBravo_PapaAlfa
{
	meta:
		copyright = "2015 Novetta Solutions"
		author = "Novetta Threat Research & Interdiction Group - trig@novetta.com"

	strings:
		$ = "pmsconfig.msi" wide
		$ = "scvrit001.bat"
	condition:
		all of them
}

rule IndiaBravo_RomeoCharlie
{
	meta:
		copyright = "2015 Novetta Solutions"
		author = "Novetta Threat Research & Interdiction Group - trig@novetta.com"
		Source = "58ad28ac4fb911abb6a20382456c4ad6fe5c8ee5.ex_"
		Status = "Signature is too loose to be useful."
		
	strings:
	/*
		50                 push    eax             ; argp
		68 7E 66 04 80     push    8004667Eh       ; cmd
		8B 8D DC FE FF FF  mov     ecx, [ebp+skt]
		51                 push    ecx             ; s
		FF 15 58 31 41 00  call    ioctlsocket
		83 F8 FF           cmp     eax, 0FFFFFFFFh
		75 08              jnz     short loc_4043F0
	*/

	$a = {
			50 
			68 7E 66 04 80 
			8B 8D [4]
			51 
			FF 15 [4] 
			83 F8 FF 
			75 
		}
	$b1 = "xc123465-efff-87cc-37abcdef9"
	$b2 = "[Check] - PORT ERROR..." wide
	$b3 = "%sd.e%sc n%ssh%srewa%s ad%s po%sop%sing T%s %d"

	condition:
		2 of ($b*) or 
		$a in ((pe.sections[pe.section_index(".text")].raw_data_offset)..(pe.sections[pe.section_index(".text")].raw_data_offset + pe.sections[pe.section_index(".text")].raw_data_size))
}

rule IndiaBravo_RomeoBravo
{
	meta:
		copyright = "2015 Novetta Solutions"
		author = "Novetta Threat Research & Interdiction Group - trig@novetta.com"
		Source = "6e3db4da27f12eaba005217eba7cd9133bc258c97fe44605d12e20a556775009"

	strings:
	/*
		E8 C3 FE FF FF     call    generate64ByteRandomNumber
		68 C8 01 00 00     push    1C8h            ; dwLength
		68 D8 E8 40 00     push    offset g_Config ; pvBuffer
		A3 80 EA 40 00     mov     dword ptr g_Config.qwIdentifier, eax
		89 15 84 EA 40 00  mov     dword ptr g_Config.qwIdentifier+4, edx
		E8 F9 E9 FF FF     call    DNSCALCDecode
		83 C4 08           add     esp, 8
		8D 4C 24 08        lea     ecx, [esp+214h+var_20C]
		6A 00              push    0
		51                 push    ecx
		68 C8 01 00 00     push    1C8h
		68 D8 E8 40 00     push    offset g_Config
		56                 push    esi
		FF 15 74 E7 40 00  call    WriteFile_9
		56                 push    esi
		FF 15 6C E7 40 00  call    CloseHandle_9
	*/

	$a = {
			E8 [4] 
			68 [2] 00 00 
			68 [4]
			A3 [4]
			89 15 [4]
			E8 [4]
			83 C4 08 
			8D [3]
			6A 00 
			5? 
			68 [2] 00 00 
			68 [4]
			5? 
			FF 15 [4]
			5? 
			FF 15 

		}
		
		$b1 = "tmscompg.msi" wide
		$b2 = "cvrit000.bat"

	condition:
		2 of ($b*) or 
		$a in ((pe.sections[pe.section_index(".text")].raw_data_offset)..(pe.sections[pe.section_index(".text")].raw_data_offset + pe.sections[pe.section_index(".text")].raw_data_size))
}


rule IndiaBravo_generic
{
	meta:
		copyright = "2015 Novetta Solutions"
		author = "Novetta Threat Research & Interdiction Group - trig@novetta.com"

	strings:
		$extractDll = "[2] - Extract Dll..." wide
		$createSvc = "[3] - CreateSVC..." wide

	condition:
		all of them
	
}

rule IndiaCharlie_One
{
	meta:
		copyright = "2015 Novetta Solutions"
		author = "Novetta Threat Research & Interdiction Group - trig@novetta.com"

	strings:
		$ = "WMPNetworkSvcUpdate"
		$ = "backSched.dll"
		$ = "\\mspaint.exe"
		$aesKey = "X,LLIe{))%%l2i<[AM|aq!Ql/lPlw]d7@C-#j.<c|#*}Kx4_H(q^F-F^p/[t#%HT"
	condition:
		2 of them or $aesKey
}

rule IndiaCharlie_Two
{
	meta:
		copyright = "2015 Novetta Solutions"
		author = "Novetta Threat Research & Interdiction Group - trig@novetta.com"

	strings:
		$s1 = "%s is an essential element in Windows System configuration and management. %s"
		$s2 = "%SYSTEMROOT%\\system32\\svchost.exe -k "
		$s3 = "%s\\system32\\%s"
		$s4 = "\\mspaint.exe"
		$s5 = ":R\nIF NOT EXIST %s GOTO E\ndel /a %s\nGOTO R\n:E\ndel /a d.bat"
		$aesKey = "}[eLkQAeEae0t@h18g!)3x-RvE%+^`n.6^()?+00ME6a&F7vcV}`@.dj]&u$o*vX"

	condition:
		3 of ($s*) or $aesKey
}

import "pe"

rule IndiaDelta
{
	meta:
		copyright = "2015 Novetta Solutions"
		author = "Novetta Threat Research & Interdiction Group - trig@novetta.com"
		Source = "d7b50b1546653bff68220996190446bdc7fc4e38373715b8848d1fb44fe3f53c"

	strings:
	/*
		FF 15 DC 2D 41 00  call    ReadFile_0
		8B 44 24 20        mov     eax, [esp+25Ch+offsetInFile]
		8B 54 24 1C        mov     edx, [esp+25Ch+dwEmbedCnt]
		35 78 56 34 12     xor     eax, 12345678h
		55                 push    ebp
		55                 push    ebp
		81 F2 78 56 34 12  xor     edx, 12345678h
		50                 push    eax
		57                 push    edi
		89 54 24 2C        mov     [esp+26Ch+dwEmbedCnt], edx
		89 44 24 30        mov     [esp+26Ch+offsetInFile], eax
		FF 15 E0 2D 41 00  call    SetFilePointer_0
	*/

	$a = {
			FF 15 [4-12] 
			3? 78 56 34 12 
			[0-2] 
			8? ?? 78 56 34 12 
			[0-10]
			FF 15
		}

	condition:
		$a in ((pe.sections[pe.section_index(".text")].raw_data_offset)..(pe.sections[pe.section_index(".text")].raw_data_offset + pe.sections[pe.section_index(".text")].raw_data_size))
}

import "pe"

rule IndiaEcho
{
	meta:
		copyright = "2015 Novetta Solutions"
		author = "Novetta Threat Research & Interdiction Group - trig@novetta.com"
		Source = "66a21f8c72bb4f314604526e9bf1736f75b06cf37dd3077eb292941b476c3235"

	strings:
	/*
		69 C0 28 01 00 00  imul    eax, 128h
		50                 push    eax             ; size_t
		53                 push    ebx             ; int
		FF B5 AC FD FF FF  push    [ebp+configRecords]; void *
		E8 6E 08 00 00     call    _memset
		8B 85 A4 FC FF FF  mov     eax, [ebp+var_35C.dwRecordCnt]
		69 C0 28 01 00 00  imul    eax, 128h
		50                 push    eax             ; size_t
		8B 85 C4 FE FF FF  mov     eax, [ebp+hMem]
		05 08 01 00 00     add     eax, 108h
		50                 push    eax             ; void *
		FF B5 AC FD FF FF  push    [ebp+configRecords]; void *
		E8 0A 05 00 00     call    _memcpy
		83 C4 18           add     esp, 18h
		8B BD A4 FC FF FF  mov     edi, [ebp+var_35C.dwRecordCnt]
		69 FF 28 01 00 00  imul    edi, 128h
		81 C7 08 01 00 00  add     edi, 108h
	*/

	$a = {
			69 ?? 28 01 00 00 
			5? 
			5? 
			FF B5 [4] 
			E8 [4] 
			8B [5] 
			69 ?? 28 01 00 00 
			50 
			8B [5] 
			(05 08 01 00 00 | 03 ??)
			50 
			FF [5]
			E8 [4] 
			83 C4 ?? 
			8B [5]
			69 ?? 28 01 00 00 
			(81 C7 08 01 00 00 | 03 ??)

		}

	condition:
		$a in ((pe.sections[pe.section_index(".text")].raw_data_offset)..(pe.sections[pe.section_index(".text")].raw_data_offset + pe.sections[pe.section_index(".text")].raw_data_size))
}

import "pe"

rule IndiaGolf
{
	meta:
		copyright = "2015 Novetta Solutions"
		author = "Novetta Threat Research & Interdiction Group - trig@novetta.com"
		Source = "3dda69dfb254dcaea2ba6e8323d4b61ab1e130a0694f4c43d336cfb86a760c50"

	strings:
	/*
		FF D6        call    esi ; rand
		8B F8        mov     edi, eax
		C1 E7 10     shl     edi, 10h
		FF D6        call    esi ; rand
		03 F8        add     edi, eax
		89 7C 24 20  mov     [esp+2A90h+var_2A70], edi
		FF D6        call    esi ; rand
		8B F8        mov     edi, eax
		C1 E7 10     shl     edi, 10h
		FF D6        call    esi ; rand
		03 F8        add     edi, eax
		89 7C 24 24  mov     [esp+2A90h+var_2A6C], edi
	*/

	$generateRandomID = {
			FF ?? 
			8B ?? 
			C1 ?? 10 
			FF ?? 
			03 F8 
			89 [3]
			FF ?? 
			8B ?? 
			C1 ?? 10 
			FF ?? 
			03 ?? 
			89 
		}

	condition:
		$generateRandomID in ((pe.sections[pe.section_index(".text")].raw_data_offset)..(pe.sections[pe.section_index(".text")].raw_data_offset + pe.sections[pe.section_index(".text")].raw_data_size))
}

import "pe"

rule IndiaHotel
{
	meta:
		copyright = "2015 Novetta Solutions"
		author = "Novetta Threat Research & Interdiction Group - trig@novetta.com"
		Source = "8a4fc5007faf85e07710dca705108df9fd6252fe3d57dfade314120d72f6d83f"

	strings:
	/*
		6A 0A              push    0Ah             ; int
		8D 85 C4 E4 FF FF  lea     eax, [ebp+Source]
		68 10 02 00 00     push    210h            ; unsigned int
		50                 push    eax             ; void *
		E8 FA 60 00 00     call    ??_L@YGXPAXIHP6EX0@Z1@Z; `eh vector constructor iterator'(void *,uint,int,void (*)(void *),void (*)(void *))
	*/

	$fileExtractorArraySetup = {
			6A 0A 
			8D [5-6]
			68 10 02 00 00 
			50 
			E8
		}

	condition:
		$fileExtractorArraySetup in ((pe.sections[pe.section_index(".text")].raw_data_offset)..(pe.sections[pe.section_index(".text")].raw_data_offset + pe.sections[pe.section_index(".text")].raw_data_size))
}

import "pe"

rule IndiaJuliett
{
	meta:
		copyright = "2015 Novetta Solutions"
		author = "Novetta Threat Research & Interdiction Group - trig@novetta.com"
		Source_writeFile = "a164c0ba0be7c33778c12a6457e9c55a2935564a"


	strings:
		$configFilename = {00 73 63 61 72 64 70 72 76  2E 64 6C 6C 00}
		$suicideScript = ":R\nIF NOT EXIST %s GOTO E\ndel /a %s\nGOTO R\n:E\ndel /a d.bat"
		$commKey = { 10 20 30 40 50 60 70 80 90 11 12 13 1A FF EE 48 }
		/*
		.text:10001850                 push    7530h           ; dwTimeout
		.text:10001855                 lea     eax, [esp+420h+a2]
		.text:10001859                 push    4               ; len
		.text:1000185B                 push    eax             ; a2
		.text:1000185C                 push    esi             ; s
		.text:1000185D                 mov     dword ptr [esp+42Ch+a2], 1000h
		.text:10001865                 call    CommSendWithTimeout
		.text:1000186A                 add     esp, 14h
		.text:1000186D                 cmp     eax, 0FFFFFFFFh
		.text:10001870                 jz      loc_10001915
		.text:10001876                 lea     ecx, [esp+418h+random]
		.text:1000187A                 push    ecx             ; a1
		.text:1000187B                 call    Generate16ByteRandomBuffer
		.text:10001880                 push    0               ; fEncrypt
		.text:10001882                 push    7530h           ; dwTimeout		
		*/
		$handshake = { 68 30 75 00 00 [4] 6A 04 5? 5? C? [3] 00 10 00 00 E8 [7] 83 F8 FF 0F 84 ?? ?? 00 00 8? [3] 5? E8 [4] 6A 00 68 30 75 00 00 }

		/*
			68 00 28 00 00     push    2800h
			56                 push    esi
			E8 38 F7 FF FF     call    sub_401000
			// optionally there is a "add esp, 8" in some variants here
			8D 44 24 28        lea     eax, [esp+270h+NumberOfBytesWritten]
			6A 00              push    0               ; lpOverlapped
			50                 push    eax             ; lpNumberOfBytesWritten
			68 00 28 00 00     push    2800h           ; nNumberOfBytesToWrite
			56                 push    esi             ; lpBuffer
			53                 push    ebx             ; hFile
			FF 15 6C 80 40 00  call    ds:WriteFile
			81 ED 00 28 00 00  sub     ebp, 2800h
			81 C7 00 28 00 00  add     edi, 2800h
			81 C6 00 28 00 00  add     esi, 2800h
		*/
	
		$writeFile = {
				68 00 28 00 00 
				5? 
				E8 [4-7] 
				8D [3] 
				6A 00 
				5? 
				68 00 28 00 00 
				5? 
				5? 
				FF 15 [4] 
				81 ?? 00 28 00 00 
				81 ?? 00 28 00 00 
				81 ?? 00 28 00 00 
			}
				
	condition:
		($configFilename in ((pe.sections[pe.section_index(".data")].raw_data_offset)..(pe.sections[pe.section_index(".data")].raw_data_offset + pe.sections[pe.section_index(".data")].raw_data_size)) or 
			$suicideScript in ((pe.sections[pe.section_index(".data")].raw_data_offset)..(pe.sections[pe.section_index(".data")].raw_data_offset + pe.sections[pe.section_index(".data")].raw_data_size)))
		or
		($handshake in ((pe.sections[pe.section_index(".rsrc")].raw_data_offset)..(pe.sections[pe.section_index(".rsrc")].raw_data_offset + pe.sections[pe.section_index(".rsrc")].raw_data_size)) and 
			$commKey in ((pe.sections[pe.section_index(".rsrc")].raw_data_offset)..(pe.sections[pe.section_index(".rsrc")].raw_data_offset + pe.sections[pe.section_index(".rsrc")].raw_data_size)))
		or
		 $writeFile in ((pe.sections[pe.section_index(".text")].raw_data_offset)..(pe.sections[pe.section_index(".text")].raw_data_offset + pe.sections[pe.section_index(".text")].raw_data_size))

}

import "pe"

rule IndiaWhiskey
{
	meta:
		copyright = "2015 Novetta Solutions"
		author = "Novetta Threat Research & Interdiction Group - trig@novetta.com"		
		Source = "0c729deec341267c5a9a2271f20266ac3b0775d70436c7770ddc20605088f3b4"
		Description = "Winsec Installer"
		
	strings:
	/*
		// Service installation code
		FF 15 68 30 40 00  call    ds:wsprintfA
		83 C4 18           add     esp, 18h
		8D 85 FC FE FF FF  lea     eax, [ebp+var_104]
		56                 push    esi
		56                 push    esi
		56                 push    esi
		56                 push    esi
		56                 push    esi
		50                 push    eax
		6A 01              push    1
		// some variants have these two lines added
		5E                 pop     esi
		56                 push    esi

		6A 02              push    2
		68 20 01 00 00     push    120h
		68 FF 01 0F 00     push    0F01FFh
		FF 75 0C           push    [ebp+arg_4]
		FF 75 08           push    [ebp+arg_0]
		
		// some variants have the next line as a push {reg} or push {stack var}
		53                 push    ebx
		//or
		FF 75 FC           push    [ebp+var_4]

		FF 15 E4 49 40 00  call    CreateServiceA
	*/

	$a = {
			FF 15 [4] 
			83 C4 18 
			8D [5] 
			5? 
			5? 
			5? 
			5? 
			5? 
			5? 
			6A 01
			[0-2] 
			6A 02 
			68 20 01 00 00 
			68 FF 01 0F 00 
			FF 75 ?? 
			FF 75 ?? 
			(5? | FF 75 ??)
			FF 15 
		}

	condition:
		$a in ((pe.sections[pe.section_index(".text")].raw_data_offset)..(pe.sections[pe.section_index(".text")].raw_data_offset + pe.sections[pe.section_index(".text")].raw_data_size))
}

import "pe"

rule KiloAlfa
{
	meta:
		copyright = "2015 Novetta Solutions"
		author = "Novetta Threat Research & Interdiction Group - trig@novetta.com"
		type = "Keylogger"
		SourceForDnscalcVariant1 = "b855d05ef7ab6582864c9b35052a1073a6eb7d0c7e9d97f524ec062715d71321"
		SourceForDnscalcVariant2 = "ddde628be8cd5db768b807510ae1319888e6c4550a5b9a0d54e17b9ec4aaa256"
		
	strings:
		/*
		push    <variable>
		call    GetAsyncKeyState
		cmp     ax, 8001h
		jnz     short loc_4021EE
		push    <variable>             ; a1
		call    AddCharacterToKeyLogBuffer
		add     esp, 4
		
		this block of code is used multiple times in sequence so i'm looking for 5 consecutive blocks
		*/
		$keyxlate = {
			68 ?? 00 00 00 FF 15 [4] 66 ?? 01 80 75 ?? 6A ?? E8 [4] 83 C4 04
			68 ?? 00 00 00 FF 15 [4] 66 ?? 01 80 75 ?? 6A ?? E8 [4] 83 C4 04
			68 ?? 00 00 00 FF 15 [4] 66 ?? 01 80 75 ?? 6A ?? E8 [4] 83 C4 04
			68 ?? 00 00 00 FF 15 [4] 66 ?? 01 80 75 ?? 6A ?? E8 [4] 83 C4 04
		}
		
	/*
		6A 2A                    push    2Ah
		C6 84 24 C4 00 00 00 D6  mov     [esp+70Ch+var_648], 0D6h
		C6 84 24 C5 00 00 00 E1  mov     [esp+70Ch+var_647], 0E1h
		C6 84 24 C6 00 00 00 BF  mov     [esp+70Ch+var_646], 0BFh
		C6 84 24 C7 00 00 00 C8  mov     [esp+70Ch+var_645], 0C8h
		C6 84 24 C8 00 00 00 C3  mov     [esp+70Ch+var_644], 0C3h
		C6 84 24 C9 00 00 00 BD  mov     [esp+70Ch+var_643], 0BDh
		88 9C 24 CA 00 00 00     mov     [esp+70Ch+var_642], bl
		FF 15 48 5B 40 00        call    GetAsyncKeyState
		66 3D 01 80              cmp     ax, 8001h
		75 20                    jnz     short loc_401696
		8D 94 24 00 01 00 00     lea     edx, [esp+708h+pszOutput]
		8D 84 24 C0 00 00 00     lea     eax, [esp+708h+var_648]
		52                       push    edx             ; pszOutput
		6A 07                    push    7               ; dwLength
		50                       push    eax             ; pszInput
		E8 A3 F9 FF FF           call    DNSCALCDecode
		50                       push    eax             ; a1
		E8 7D FB FF FF           call    AddEntryToKeylogDataBuffer
		83 C4 10                 add     esp, 10h
	*/

	$keyxlateDnscalc1 = {	6A 2A C6 [6] D6 C6 [6] E1 C6 [6] BF C6 [6] C8 C6 [6] C3 C6 [6] BD	88 [6] FF 15 [4] 66 3D 01 80 75 ?? 	8D [6] 8D [6] 5? 6A 07 5? E8 [4] 50 E8 [4] 83 C4 10 }	

	/*
		6A 2A                          push    2Ah
		C7 85 74 FF FF FF D6 E1 BF C8  mov     dword ptr [ebp+var_8C], 0C8BFE1D6h
		66 C7 85 78 FF FF FF C3 BD     mov     [ebp+var_88], 0BDC3h
		88 9D 7A FF FF FF              mov     [ebp+var_86], bl
		FF 15 04 47 41 00              call    GetAsyncKeyState
		BA 01 80 FF FF                 mov     edx, 0FFFF8001h
		66 3B C2                       cmp     ax, dx
		75 1E                          jnz     short loc_4018B0
		8D 85 CC FE FF FF              lea     eax, [ebp+a3]
		50                             push    eax             ; a3
		8D 8D 74 FF FF FF              lea     ecx, [ebp+var_8C]
		6A 07                          push    7               ; dwLength
		51                             push    ecx             ; a1
		E8 89 F7 FF FF                 call    DNSCalcDecode
		50                             push    eax             ; a1
		E8 83 F9 FF FF                 call    RecordStringToLog
		83 C4 10                       add     esp, 10h
	*/

	$keyxlateDnscalc2 = { 6A 2A C7 [5] D6 E1 BF C8 	66 [6] C3 BD 88 [5]	FF 15 [4] BA 01 80 FF FF 66 3B C2 75 ?? 8D [5] 5? 8D [5] 6A 07 5? E8 [4] 50 E8 [4] 83 C4 10 }
	
	condition: 
		$keyxlate in ((pe.sections[pe.section_index(".text")].raw_data_offset)..(pe.sections[pe.section_index(".text")].raw_data_offset + pe.sections[pe.section_index(".text")].raw_data_size))
		or $keyxlateDnscalc1 in ((pe.sections[pe.section_index(".text")].raw_data_offset)..(pe.sections[pe.section_index(".text")].raw_data_offset + pe.sections[pe.section_index(".text")].raw_data_size))
		or $keyxlateDnscalc2 in ((pe.sections[pe.section_index(".text")].raw_data_offset)..(pe.sections[pe.section_index(".text")].raw_data_offset + pe.sections[pe.section_index(".text")].raw_data_size))
	
}

import "pe"

rule LimaAlfa
{
	meta:
		copyright = "2015 Novetta Solutions"
		author = "Novetta Threat Research & Interdiction Group - trig@novetta.com"
		Source = "c9fbad7fc7ff7688776056be3a41714a1f91458a7b16c37c3c906d17daac2c8b"
		Status = "Signature is too loose to be useful."

	strings:
	/*
		33 C0              xor     eax, eax
		66 8B 02           mov     ax, [edx]
		8B E8              mov     ebp, eax
		81 E5 00 F0 FF FF  and     ebp, 0FFFFF000h
		81 FD 00 30 00 00  cmp     ebp, 3000h
		75 0D              jnz     short loc_4019FB
		8B 6C 24 18        mov     ebp, [esp+10h+arg_4]
		25 FF 0F 00 00     and     eax, 0FFFh
		03 C7              add     eax, edi
		01 28              add     [eax], ebp
	*/

	$a = {
			33 C0 
			66 [2] 
			8B ?? 
			81 ?? 00 F0 FF FF 
			81 ?? 00 30 00 00 
			75 ?? 
			8B [3] 
			25 FF 0F 00 00 
			03 C7 
			01 
		}

	condition:
		$a in ((pe.sections[pe.section_index(".text")].raw_data_offset)..(pe.sections[pe.section_index(".text")].raw_data_offset + pe.sections[pe.section_index(".text")].raw_data_size))
}

import "pe"

rule LimaBravo
{
	meta:
		copyright = "2015 Novetta Solutions"
		author = "Novetta Threat Research & Interdiction Group - trig@novetta.com"
		Source = "Mwsagent.dll"

	strings:
	/*
		83 C4 34        add     esp, 34h
		83 FD 0A        cmp     ebp, 0Ah
		5D              pop     ebp
		5B              pop     ebx
		7E 12           jle     short loc_1000106F
		57              push    edi             ; Src
		C6 07 4D        mov     byte ptr [edi], 4Dh
		C6 47 01 5A     mov     byte ptr [edi+1], 5Ah
		E8 97 01 00 00  call    ManualImageLoad
	*/

	$a = {
			83 ?? 34 
			83 ?? 0A 
			[0-2] 
			7E ?? 
			5? 
			C6 ?? 4D 
			C6 [2] 5A 
			E8 
		}

	condition:
		$a in ((pe.sections[pe.section_index(".text")].raw_data_offset)..(pe.sections[pe.section_index(".text")].raw_data_offset + pe.sections[pe.section_index(".text")].raw_data_size))
}

import "pe"

rule LimaCharlie
{
	meta:
		copyright = "2015 Novetta Solutions"
		author = "Novetta Threat Research & Interdiction Group - trig@novetta.com"
		Source_x86 = "6ee6ae79ee1502a11ece81e971a54f189a271be9ec700101a2bd7a21198b94c7"
		Source_x64 = "90ace24eb132c776a6d5bb0451437db21e84601495a2165d75f520af637e71e8"

	strings:
		$misspelling = "Defualt Sleep = %d" wide

	/*
		FF 76 74           push    dword ptr [esi+74h]
		59                 pop     ecx
		50                 push    eax
		8F 86 48 01 00 00  pop     dword ptr [esi+148h]
		85 C0              test    eax, eax
		51                 push    ecx
		8F 86 44 01 00 00  pop     dword ptr [esi+144h]
		75 3D              jnz     short loc_100035F3
		F6 46 56 01        test    byte ptr [esi+56h], 1
		74 0A              jz      short loc_100035C6
	*/

	$x86 = {
			FF ?? 74 
			5? 
			5? 
			8F ?? 48 01 00 00 
			85 C0 
			5? 
			8F ?? 44 01 00 00 
			75 ?? 
			F6 [2] 01 
			74 
		}

	/*
		48 8B 4B 70           mov     rcx, [rbx+70h]
		48 89 8B 60 01 00 00  mov     [rbx+160h], rcx
		48 89 83 68 01 00 00  mov     [rbx+168h], rax
		48 85 C0              test    rax, rax
		75 35                 jnz     short loc_180002372
		F6 43 56 01           test    byte ptr [rbx+56h], 1
		74 07                 jz      short loc_18000234A
	*/

	$x64 = {
			48 [2] 70 
			48 [2] 60 01 00 00 
			48 [2] 68 01 00 00 
			48 85 C0 
			75 ?? 
			F6 [2] 01 
			74 
		}
		
	condition:
		$x86 in ((pe.sections[pe.section_index(".text")].raw_data_offset)..(pe.sections[pe.section_index(".text")].raw_data_offset + pe.sections[pe.section_index(".text")].raw_data_size))
		or $x64 in ((pe.sections[pe.section_index(".text")].raw_data_offset)..(pe.sections[pe.section_index(".text")].raw_data_offset + pe.sections[pe.section_index(".text")].raw_data_size))
		or $misspelling
		
}


import "pe"

rule LimaDelta
{
	meta:
		copyright = "2015 Novetta Solutions"
		author = "Novetta Threat Research & Interdiction Group - trig@novetta.com"
		Source = "81e6118a6d8bf8994ce93f940059217481bfd15f2757c48c589983a6af54cfcc"

	strings:
	/*
		8B 69 FC           mov     ebp, [ecx-4]
		83 C1 10           add     ecx, 10h
		81 F5 6D 3A 71 58  xor     ebp, 58713A6Dh
		89 2A              mov     [edx], ebp
		33 ED              xor     ebp, ebp
		66 8B 69 F0        mov     bp, [ecx-10h]
		89 6A 04           mov     [edx+4], ebp
		83 C2 08           add     edx, 8
		4F                 dec     edi
		75 E3              jnz     short loc_4026CE
	*/

	$fileDecoder = {
			8B ?? ?? 
			83 ?? 10 
			81 ?? 6D 3A 71 58 
			89 ?? 
			33 ?? 
			66 ?? ?? F0 
			89 ?? 04 
			83 ?? 08 
			4? 
			75 
		}
		
	/*
		66 81 BC 24 A0 00 00 00 BB 01  cmp     [esp+98h+arg_4], 1BBh
		74 21                          jz      short loc_401BD7
		FF 15 58 30 40 00              call    ds:rand
		99                             cdq
		B9 32 00 00 00                 mov     ecx, 32h
		F7 F9                          idiv    ecx
		8B DA                          mov     ebx, edx
		8D 54 24 5E                    lea     edx, [esp+98h+var_3A]
		53                             push    ebx             ; dwSize
		52                             push    edx             ; pvBuffer
		E8 3F FB FF FF                 call    GenerateRandomBuffer
		83 C4 08                       add     esp, 8
		83 C3 46                       add     ebx, 46h
	*/

	$authenicateBufferGen = {
			BB 01 
			74 ??
			FF 15 [4]
			99 
			B? 32 00 00 00 
			F7 ?? 
			8B ?? 
			8D [3]
			5? 
			5? 
			E8 [4]
			83 C4 08 
			83 ?? 46 
		}
	
	condition:
		$authenicateBufferGen in ((pe.sections[pe.section_index(".text")].raw_data_offset)..(pe.sections[pe.section_index(".text")].raw_data_offset + pe.sections[pe.section_index(".text")].raw_data_size))
		or $fileDecoder in ((pe.sections[pe.section_index(".text")].raw_data_offset)..(pe.sections[pe.section_index(".text")].raw_data_offset + pe.sections[pe.section_index(".text")].raw_data_size))
}


rule PapaAlfa
{
	meta:
		copyright = "2015 Novetta Solutions"
		author = "Novetta Threat Research & Interdiction Group - trig@novetta.com"

	strings:
		$ = "pmsconfig.msi" wide
		$ = "pmslog.msi" wide
		$ = "%sd.e%sc n%ssh%srewa%s ad%s po%sop%sing T%s %d"
		$ = "CreatP2P Thread" wide
		$ = "GreatP2P Thread" wide
	condition:
		3 of them
}

import "pe"

rule RomeoAlfa
{
	meta:
		copyright = "2015 Novetta Solutions"
		author = "Novetta Threat Research & Interdiction Group - trig@novetta.com"
		Source = "fba0b8bdc1be44d100ac31b864830fcc9d056f1f5ab5486384e09bd088256dd0.file2.bin"

	strings:
	/*
		68 C4 94 41 00     push    offset a0_0_0_0 ; "0.0.0.0"
		56                 push    esi             ; wchar_t *
		E8 1C B4 00 00     call    _wcscpy
		83 C6 28           add     esi, 28h
		83 C4 08           add     esp, 8
		81 FE E8 CD 41 00  cmp     esi, offset unk_41CDE8
		7C E7              jl      short loc_4039DA
	*/

	$zeroIPLoader = {
			68 [4] 
			56 
			E8 [4] 
			83 C6 28 
			83 C4 08 
			81 FE [4] 
			7C E? 
		}
		


		// push    esi                              
		// mov     esi, [esp+4+a1]                  
		// test    esi, esi                         
		// jle     short loc_403FEB                 
		// push    edi                              
		// mov     edi, ds:Sleep                    
		// push    0EA60h          ; dwMilliseconds 
		// call    edi ; Sleep                      
		// dec     esi                              
		// jnz     short loc_403FE0                 
		// pop     edi                              
		// pop     esi                              
		// retn                                     
		$sleeper  = {
				5? 
				8B [3]                       
				85 ??                        
				7E ??                        
				5? 
				8B 3D [4]                    
				68 [4]               
				FF ??                        
				4? 
				75 ??                        
				5? 
				5? 
				C3                           
			}
			
		$xercesc = "xercesc"
		
	condition:
		($sleeper in ((pe.sections[pe.section_index(".text")].raw_data_offset)..(pe.sections[pe.section_index(".text")].raw_data_offset + pe.sections[pe.section_index(".text")].raw_data_size))
		or $zeroIPLoader in ((pe.sections[pe.section_index(".text")].raw_data_offset)..(pe.sections[pe.section_index(".text")].raw_data_offset + pe.sections[pe.section_index(".text")].raw_data_size)))
		and not $xercesc
}


import "pe"

rule RomeoBravo
{
	meta:
		copyright = "2015 Novetta Solutions"
		author = "Novetta Threat Research & Interdiction Group - trig@novetta.com"
		Source = "95314a7af76ec36cfba1a02b67c2b81526a04e3b2f9b8fb9b383ffcbcc5a3d9b"

	strings:
	/*
		E8 D9 FC FF FF  call    SendData
		83 C4 10        add     esp, 10h
		85 C0           test    eax, eax
		74 0A           jz      short loc_10003FE8
		B8 02 00 00 00  mov     eax, 2
		5E              pop     esi
		83 C4 18        add     esp, 18h
		C3              retn
		6A 78           push    78h             ; dwTimeout
		6A 01           push    1               ; fDecode
		8D 54 24 18     lea     edx, [esp+24h+recvData]
		6A 0C           push    0Ch             ; dwLength
		52              push    edx             ; pvBuffer
		56              push    esi             ; skt
		E8 57 FD FF FF  call    RecvData
		83 C4 14        add     esp, 14h
		85 C0           test    eax, eax
		74 0A           jz      short loc_1000400A
		B8 02 00 00 00  mov     eax, 2
	*/

	$a = {
			E8 [4] 
			83 C4 10 
			85 C0 
			74 ?? 
			B? 02 00 00 00 
			5? 
			83 C4 18 
			C3 
			6A 78 
			6A 01 
			8D [3]
			6A 0C 
			5? 
			5? 
			E8 [4]
			83 C4 14 
			85 C0 
			74 ?? 
			B8 02 00 00 00 
		}

	condition:
		$a in ((pe.sections[pe.section_index(".text")].raw_data_offset)..(pe.sections[pe.section_index(".text")].raw_data_offset + pe.sections[pe.section_index(".text")].raw_data_size))
}

import "pe"

rule RomeoCharlie
{
	meta:
		copyright = "2015 Novetta Solutions"
		author = "Novetta Threat Research & Interdiction Group - trig@novetta.com"
		Source = "a82108ef7115931b3fbe1fab99448c4139e22feda27c1b1d29325710671154e8"

	strings:
		$auth1 = "Success - Accept Auth"
		$auth2 = "Fail - Accept Auth"

	/*
		81 E3 FF FF 00 00  and     ebx, 0FFFFh
		8B EB              mov     ebp, ebx
		57                 push    edi
		C1 EE 10           shr     esi, 10h
		81 E5 FF FF 00 00  and     ebp, 0FFFFh
		8B FE              mov     edi, esi
		8B C5              mov     eax, ebp
		81 E7 FF FF 00 00  and     edi, 0FFFFh
		C1 E0 10           shl     eax, 10h
		6A 00              push    0               ; _DWORD
		0B C7              or      eax, edi
		6A 00              push    0               ; _DWORD
		50                 push    eax             ; _DWORD
		68 10 14 11 71     push    offset sub_71111410; _DWORD
		6A 00              push    0               ; _DWORD
		6A 00              push    0               ; _DWORD
		FF 15 5C 8E 12 71  call    CreateThread_0
		C1 E7 10           shl     edi, 10h
	*/

	$startupRelayThreads = {
			81 ?? FF FF 00 00 
			8B ?? 
			5? 
			C1 ?? 10 
			81 ?? FF FF 00 00 
			8B ?? 
			8B ?? 
			81 ?? FF FF 00 00 
			C1 ?? 10 
			6A 00 
			0B ?? 
			6A 00 
			50 
			68 [4] 
			6A 00 
			6A 00 
			FF 15 [4] 
			C1 ?? 10 
		}

	/*
	source: 641808833ad34f2e5143001c8147d779dbfd2a80a80ce0cfc81474d422882adb
		25 00 20 00 00     and     eax, 2000h
		3D 00 20 00 00     cmp     eax, 2000h
		0F 94 C1           setz    cl
		81 E2 80 00 00 00  and     edx, 80h
		33 C0              xor     eax, eax
		80 FA 80           cmp     dl, 80h
		0F 94 C0           setz    al
		03 C8              add     ecx, eax
		33 D2              xor     edx, edx
		83 F9 01           cmp     ecx, 1
	*/

	$crypto = {
			2? 00 20 00 00 
			3? 00 20 00 00 
			0F [2] 
			81 ?? 80 00 00 00 
			33 ?? 
			80 ?? 80 
			0F [2] 
			03 ?? 
			33 ?? 
			83 ?? 01 
		}

	condition:
		all of ($auth*) 
		or $startupRelayThreads in ((pe.sections[pe.section_index(".text")].raw_data_offset)..(pe.sections[pe.section_index(".text")].raw_data_offset + pe.sections[pe.section_index(".text")].raw_data_size))
		or $crypto in ((pe.sections[pe.section_index(".text")].raw_data_offset)..(pe.sections[pe.section_index(".text")].raw_data_offset + pe.sections[pe.section_index(".text")].raw_data_size))
}


import "pe"

rule RomeoDelta
{
	meta:
		copyright = "2015 Novetta Solutions"
		author = "Novetta Threat Research & Interdiction Group - trig@novetta.com"
		Source = "1df2af99fb3b6e31067b06df07b96d0ed0632f85111541a416da9ceda709237c"

	strings:
	/*
		E8 78 00 00 00  call    GenerateRandomBuffer
		33 C0           xor     eax, eax
		8A 4C 04 04     mov     cl, [esp+eax+24h+buffer]
		80 E9 22        sub     cl, 22h
		80 F1 AD        xor     cl, 0ADh
		88 4C 04 04     mov     [esp+eax+24h+buffer], cl
		40              inc     eax
		83 F8 10        cmp     eax, 10h
		7C EC           jl      short loc_1000117A
		6A 01           push    1               ; fEncode
		8D 54 24 08     lea     edx, [esp+28h+buffer]
		6A 10           push    10h             ; dwDataLength
		52              push    edx             ; pvData
		8B CB           mov     ecx, ebx        ; this
		E8 A2 00 00 00  call    CSocket__Send
	*/

	$loginInit = { E8 [4] 33 C0 8A [3] 80 [2] 80 [2] 88 [3] 40 83 F8 10 7C ?? 6A 01 8D [3] 6A 10 5? 8B CB E8	}

	condition:
		$loginInit in ((pe.sections[pe.section_index(".text")].raw_data_offset)..(pe.sections[pe.section_index(".text")].raw_data_offset + pe.sections[pe.section_index(".text")].raw_data_size))
}


import "pe"

rule RomeoEcho
{
	meta:
		copyright = "2015 Novetta Solutions"
		author = "Novetta Threat Research & Interdiction Group - trig@novetta.com"

	strings:
		$ = "%s %-20s %10lu %s"
		$ = "_quit"
		$ = "_exe"
		$ = "_put"
		$ = "_get"

	condition:
		all of them
}


import "pe"


rule RomeoFoxtrot
{
	meta:
		copyright = "2015 Novetta Solutions"
		author = "Novetta Threat Research & Interdiction Group - trig@novetta.com"
		Source = "dropped.bin"
		Source_relativeCalls = "635bebe95671336865f8a546f06bf67ab836ea35795581d8a473ef2cd5ff4a7f"

	strings:
	/*
		C7 44 24 08 01 00 00 00  mov     [esp+128h+argp], 1
		8B 8C 24 30 01 00 00     mov     ecx, dword ptr [esp+128h+wPort]
		C7 44 24 04 00 00 20 03  mov     dword ptr [esp+128h+optval], 3200000h
		51                       push    ecx             ; hostshort
		89 44 24 1C              mov     dword ptr [esp+12Ch+name.sin_addr.S_un], eax
		FF 15 8C 01 FF 7E        call    ds:htons
		6A 06                    push    6               ; protocol
		6A 01                    push    1               ; type
		6A 02                    push    2               ; af
		66 89 44 24 22           mov     [esp+134h+name.sin_port], ax
		66 C7 44 24 20 02 00     mov     [esp+134h+name.sin_family], 2
		FF 15 84 01 FF 7E        call    ds:socket								     <--- this could be a relative call in some variants
		83 F8 FF                 cmp     eax, 0FFFFFFFFh
		89 46 04                 mov     [esi+4], eax
		0F 84 AD 00 00 00        jz      loc_7EFE4C63
		57                       push    edi
		8B 3D 88 01 FF 7E        mov     edi, ds:setsockopt            <---- this line is missing when relative calls are used
		8D 54 24 08              lea     edx, [esp+12Ch+optval]
		6A 04                    push    4               ; optlen
		52                       push    edx             ; optval
		68 02 10 00 00           push    1002h           ; optname
		68 FF FF 00 00           push    0FFFFh          ; level
		50                       push    eax             ; s
		FF D7                    call    edi ; setsockopt								<--- this could be a relative call in some variants
		8B 4E 04                 mov     ecx, [esi+4]
		8D 44 24 08              lea     eax, [esp+12Ch+optval]
		6A 04                    push    4               ; optlen
		50                       push    eax             ; optval
		68 01 10 00 00           push    1001h           ; optname
		68 FF FF 00 00           push    0FFFFh          ; level
		51                       push    ecx             ; s
		FF D7                    call    edi ; setsockopt								<--- this could be a relative call in some variants
	*/

		//$connect = {C7 [3] 01 00 00 00 8B [6] C7 [3] 00 00 20 03 5? 89 [3] (FF 15 [4] | E8 [4]) 6A 06 6A 01 6A 02 66 [4] 66 [4] 02 00 (FF 15 [4] | E8 [4]) 83 F8 FF 89 [2] 0F 84 [4] [0-7] 8D [3] 6A 04 5? 68 02 10 00 00 68 FF FF 00 00 5? (FF D? | E8 [4]) 8B [2] 8D [3] 6A 04 5? 68 01 10 00 00 68 FF FF 00 00 5? (FF D? | E8 [4])}
		$connect = {C7 [3] 01 00 00 00 8B [6] C7 [3] 00 00 20 03 5? 89 [3] FF 15 [4] 6A 06 6A 01 6A 02 66 [4] 66 [4] 02 00 FF 15 E8 [4] 83 F8 FF 89 [2] 0F 84 [4] [0-7] 8D [3] 6A 04 5? 68 02 10 00 00 68 FF FF 00 00 5? FF D? 8B [2] 8D [3] 6A 04 5? 68 01 10 00 00 68 FF FF 00 00 5? FF D?}
		$challenge = "POST HTTP REQUEST?"
        $response = "RESPONSE 200 OK!!!"

	condition:
		($challenge and $response) or 
		$connect in ((pe.sections[pe.section_index(".text")].raw_data_offset)..(pe.sections[pe.section_index(".text")].raw_data_offset + pe.sections[pe.section_index(".text")].raw_data_size))
}

import "pe"

rule RomeoGolf
{
	meta:
		copyright = "2015 Novetta Solutions"
		author = "Novetta Threat Research & Interdiction Group - trig@novetta.com"
		Source = "7322d6b9328a9c708518c99b03a4ed3aa6ba943d7b439f6b1925e6d52a1828fe"

	strings:
	/*
		FF 15 70 80 01 10  call    ds:GetTickCount
		50                 push    eax             ; unsigned int
		E8 80 93 00 00     call    _srand
		83 C4 04           add     esp, 4
		E8 85 93 00 00     call    _rand
		C1 E0 10           shl     eax, 10h
		89 46 0C           mov     [esi+0Ch], eax
		E8 7A 93 00 00     call    _rand
		01 46 0C           add     [esi+0Ch], eax
		E8 72 93 00 00     call    _rand
		C1 E0 10           shl     eax, 10h
		89 46 08           mov     [esi+8], eax
		E8 67 93 00 00     call    _rand
		01 46 08           add     [esi+8], eax
	*/

	$idGen = {FF 15 [4] 50 E8 [4] 83 C4 04 E8 [4] C1 ?? 10 89 [2] E8 [4] 01 [2] E8 [4] C1 ?? 10 89 [2] E8 [4] ?? ?? ?? }
	condition:
		$idGen in ((pe.sections[pe.section_index(".text")].raw_data_offset)..(pe.sections[pe.section_index(".text")].raw_data_offset + pe.sections[pe.section_index(".text")].raw_data_size))
}


import "pe"

rule RomeoHotel
{
	meta:
		copyright = "2015 Novetta Solutions"
		author = "Novetta Threat Research & Interdiction Group - trig@novetta.com"
		Source_64 = "440cb3f6dd07e2f9e3d3614fd23d3863ecfc08b463b0b327eedf08504f838c90"
		Source_diskSpace = "1b1496f8f35d32a93c7f16ebff6e9b560a158cc6fce061491f91bc9f43ef5be4"

	strings:
	/*
		E8 D3 C7 00 00  call    rand
		44 8B ED        mov     r13d, ebp
		44 8B E0        mov     r12d, eax
		B8 1F 85 EB 51  mov     eax, 51EB851Fh
		48 8B FD        mov     rdi, rbp
		41 F7 EC        imul    r12d
		C1 FA 05        sar     edx, 5
		8B CA           mov     ecx, edx
		C1 E9 1F        shr     ecx, 1Fh
		03 D1           add     edx, ecx
		6B D2 64        imul    edx, 64h
		44 2B E2        sub     r12d, edx
		41 83 C4 3C     add     r12d, 3Ch
	*/

	$randBuff64 = {
			E8 [4]
			44 [2]
			44 [2] 
			B? 1F 85 EB 51 
			48 [2] 
			41 [2]
			C1 ?? 05 
			8B ?? 
			C1 ?? 1F 
			03 ?? 
			6B ?? 64 
			44 [2] 
			41 [2] 3C 
		}
		
	/*
		FF 15 40 70 01 10     call    ds:GetDiskFreeSpaceExA
		85 C0                 test    eax, eax
		74 34                 jz      short loc_10005072
		8B 84 24 20 01 00 00  mov     eax, [esp+11Ch+arg_0]
		6A 00                 push    0
		99                    cdq
		68 00 00 10 00        push    100000h
		52                    push    edx
		50                    push    eax
		E8 4C 7C 00 00        call    __allmul
	*/

	$diskSpace = {
			FF 15 [4]
			85 C0 
			74 ??
			8B [6]
			6A 00 
			99 
			68 00 00 10 00 
			5? 
			5? 
			E8
		}
		
	$winst = "winsta0\\default" wide		// this limits the overlap with RomeoGolf

	condition:
		$randBuff64 in ((pe.sections[pe.section_index(".text")].raw_data_offset)..(pe.sections[pe.section_index(".text")].raw_data_offset + pe.sections[pe.section_index(".text")].raw_data_size))
		or ($diskSpace in ((pe.sections[pe.section_index(".text")].raw_data_offset)..(pe.sections[pe.section_index(".text")].raw_data_offset + pe.sections[pe.section_index(".text")].raw_data_size))
		and $winst)
}

// rules specific to the winsec malware families
import "pe"

rule RomeoWhiskey_Two
{
	meta:
		copyright = "2015 Novetta Solutions"
		author = "Novetta Threat Research & Interdiction Group - trig@novetta.com"
		Source = "a8d88714f0bc643e76163d1b8972565e78a159292d45a8218d0ad0754c8f561d"

	strings:
	/*
		FF 15 78 A2 00 10  call    GetTickCount_9
		66 8B C8           mov     cx, ax

		// the next op is a mov or a push/pop depending on the code version
		53                 push    ebx
		8F 45 F4           pop     dword ptr [ebp-0Ch]
		//or
		89 5D F4           mov     dword ptr [ebp+var_C], ebx
		
		
		66 81 F1 40 1C     xor     cx, 1C40h
		66 D1 E9           shr     cx, 1
		81 C1 E0 56 00 00  add     ecx, 56E0h
		0F B7 C9           movzx   ecx, cx
		0F B7 C0           movzx   eax, ax
		81 F1 30 32 00 00  xor     ecx, 3230h
		C1 E0 10           shl     eax, 10h
		0B C8              or      ecx, eax
	*/

	$a = {
			FF 15 [4] 
			66 8B C8 
			[3-4] 
			66 81 F1 40 1C 
			66 D1 E9 
			81 C1 E0 56 00 00 
			0F B7 C9 
			0F B7 C0 
			81 F1 30 32 00 00 
			C1 E0 10 
			0B C8 
		}

	condition:
		$a in ((pe.sections[pe.section_index(".text")].raw_data_offset)..(pe.sections[pe.section_index(".text")].raw_data_offset + pe.sections[pe.section_index(".text")].raw_data_size))
}



rule RomeoWhiskey_One
{
	meta:
		copyright = "2015 Novetta Solutions"
		author = "Novetta Threat Research & Interdiction Group - trig@novetta.com"
		Source = "5d21e865d57e9798ac7c14a6ad09c4034d103f3ea993295dcdf8a208ea825ad7"

	strings:
	/*
		FF 15 D8 5B 00 10  call    GetTickCount_9
		0F B7 C0           movzx   eax, ax
		8B C8              mov     ecx, eax
		// skipped: 6A 01              push    1               ; fDecode
		C1 E9 34           shr     ecx, 34h         <--- this value could change
		81 F1 C0 F3 00 00  xor     ecx, 0F3C0h			<--- this value could change
		// skipped: 6A 04              push    4               ; dwLength
		C1 E0 10           shl     eax, 10h
		0B C8              or      ecx, eax
	*/

	$a = {
			FF 15 [4]  
			0F B7 C0
			8B C8
			[2-4] 
			C1 E9 ?? 
			81 F1 [2] 00 00 
			[0-2] 
			C1 E0 10 
			0B C8 
		}

	condition:
		$a in ((pe.sections[pe.section_index(".text")].raw_data_offset)..(pe.sections[pe.section_index(".text")].raw_data_offset + pe.sections[pe.section_index(".text")].raw_data_size))
}

// sigs for the various cross-family codes
import "pe"

rule Caracachs: sharedcode
{
	meta:
		copyright = "2015 Novetta Solutions"
		author = "Novetta Threat Research & Interdiction Group - trig@novetta.com"
		Source = "eff542ac8e37db48821cb4e5a7d95c044fff27557763de3a891b40ebeb52cc55.ex_"

	strings:
	/*
		B9 10 00 00 00     mov     ecx, 10h        ; ecx = 16
		8B 06              mov     eax, [esi]      ; eax = lastValue
		C1 EA 10           shr     edx, 10h        ; edx = val >> 16
		81 E2 FF 7F 00 00  and     edx, 7FFFh      ; edx = (val >> 16) & 0x7FFF
		03 C2              add     eax, edx        ; eax = ((val >> 16) & 0x7FFF) + lastValue
		8B D0              mov     edx, eax        ; edx = ((val >> 16) & 0x7FFF) + lastValue
		8B F8              mov     edi, eax        ; edi = ((val >> 16) & 0x7FFF) + lastValue
		83 E2 0F           and     edx, 0Fh        ; edx = (((val >> 16) & 0x7FFF) + lastValue) & 0xF
		2B CA              sub     ecx, edx        ; ecx = 16 - ((((val >> 16) & 0x7FFF) + lastValue)) & 0xF
		D3 EF              shr     edi, cl         ; edi = (((val >> 16) & 0x7FFF) + lastValue) >> ((16 - ((val >> 16) & 0x7FFF) + lastValue) & 0xF)
		8B CA              mov     ecx, edx        ; ecx = (((val >> 16) & 0x7FFF) + lastValue) & 0xF
		D3 E0              shl     eax, cl         ; eax = (((val >> 16) & 0x7FFF) + lastValue) << ((((val >> 16) & 0x7FFF) + lastValue) & 0xF)
		0B F8              or      edi, eax        ; edi = (((val >> 16) & 0x7FFF) + lastValue) >> ((16 - ((val >> 16) & 0x7FFF) + lastValue) & 0xF) | (((val >> 16) & 0x7FFF) + lastValue) << ((((val >> 16) & 0x7FFF) + lastValue) & 0xF)
		89 3E              mov     [esi], edi      ; pLastValue = (((val >> 16) & 0x7FFF) + lastValue) >> ((16 - ((val >> 16) & 0x7FFF) + lastValue) & 0xF) | (((val >> 16) & 0x7FFF) + lastValue) << ((((val >> 16) & 0x7FFF) + lastValue) & 0xF)
	*/

	$a = {
			B? 10 00 00 00 
			8B ?? 
			C1 ?? 10 
			81 ?? FF 7F 00 00 
			03 ?? 
			8B ?? 
			8B ?? 
			83 ?? 0F 
			2B ?? 
			D3 ?? 
			8B ?? 
			D3 ?? 
			0B ?? 
			89 ?? 
		}

	condition:
		$a in ((pe.sections[pe.section_index(".text")].raw_data_offset)..(pe.sections[pe.section_index(".text")].raw_data_offset + pe.sections[pe.section_index(".text")].raw_data_size))
}


rule StringDotSimplified: sharedcode
{
	meta:
		copyright = "2015 Novetta Solutions"
		author = "Novetta Threat Research & Interdiction Group - trig@novetta.com"
		Source = "eff542ac8e37db48821cb4e5a7d95c044fff27557763de3a891b40ebeb52cc55.ex_"

	strings:
	/*
		F3 AB     rep stosd
		80 3A 00  cmp     byte ptr [edx], 0
		74 15     jz      short loc_404170
		8A 02     mov     al, [edx]
		3C 2E     cmp     al, 2Eh
		74 07     jz      short loc_404168
		3C 20     cmp     al, 20h
		74 03     jz      short loc_404168
		88 06     mov     [esi], al
		46        inc     esi
	*/

	$a = {
			F3 AB 
			80 ?? 00 
			74 ?? 
			8A 02 
			3C 2E 
			74 ?? 
			3C 20 
			74 ?? 
			88 06 
			46 
		}

	condition:
		$a in ((pe.sections[pe.section_index(".text")].raw_data_offset)..(pe.sections[pe.section_index(".text")].raw_data_offset + pe.sections[pe.section_index(".text")].raw_data_size))
}

rule FakeTLS_ServerHelloGetSelectedCipher: sharedcode
{
	meta:
		copyright = "2015 Novetta Solutions"
		author = "Novetta Threat Research & Interdiction Group - trig@novetta.com"
		Source = "eff542ac8e37db48821cb4e5a7d95c044fff27557763de3a891b40ebeb52cc55.ex_"

	strings:
	/*
		24 10           and     al, 10h
		0C 10           or      al, 10h
		89 07           mov     [edi], eax
		66 8B 44 24 14  mov     ax, [esp+0Ch+wCipherSuiteID]
		66 3D 00 C0     cmp     ax, 0C000h
		73 34           jnb     short loc_4067C1
		66 2D 35 00     sub     ax, 35h
		66 F7 D8        neg     ax
		1B C0           sbb     eax, eax
		24 80           and     al, 80h
		05 00 01 00 00  add     eax, 100h
		8B D8           mov     ebx, eax
		53              push    ebx             ; hostshort
	*/

	$a = {
			24 10 
			0C 10 
			89 ?? 
			66 8? [3]
			66 3? 00 C0 
			73 ?? 
			66 2? 35 00 
			66 F7 ?? 
			1B ?? 
			2? 80 
			0? 00 01 00 00 
			8B ?? 
			5? 
		}

	condition:
		$a in ((pe.sections[pe.section_index(".text")].raw_data_offset)..(pe.sections[pe.section_index(".text")].raw_data_offset + pe.sections[pe.section_index(".text")].raw_data_size))
}

rule XORDecodeA7: sharedcode
{
	meta:
		copyright = "2015 Novetta Solutions"
		author = "Novetta Threat Research & Interdiction Group - trig@novetta.com"
		Source = "eff542ac8e37db48821cb4e5a7d95c044fff27557763de3a891b40ebeb52cc55.ex_"

	strings:
	/*
		8A 04 17  mov     al, [edi+edx]
		8B FB     mov     edi, ebx
		34 A7     xor     al, 0A7h
		46        inc     esi
		88 02     mov     [edx], al
		83 C9 FF  or      ecx, 0FFFFFFFFh
		33 C0     xor     eax, eax
		42        inc     edx
		F2 AE     repne scasb
		F7 D1     not     ecx
		49        dec     ecx
		3B F1     cmp     esi, ecx
	*/

	$a = {
			8A [2] 
			8B ??
			34 A7 
			46 
			88 ?? 
			83 ?? FF 
			33 ?? 
			4? 
			F2 AE 
			F7 ?? 
			4? 
			3B ?? 
		}

	condition:
		$a in ((pe.sections[pe.section_index(".text")].raw_data_offset)..(pe.sections[pe.section_index(".text")].raw_data_offset + pe.sections[pe.section_index(".text")].raw_data_size))
}


rule DynamicAPILoading: sharedcode
{
	meta:
		copyright = "2015 Novetta Solutions"
		author = "Novetta Threat Research & Interdiction Group - trig@novetta.com"
		Source = "eff542ac8e37db48821cb4e5a7d95c044fff27557763de3a891b40ebeb52cc55.ex_"

	strings:
	/*
		83 C4 04           add     esp, 4
		50                 push    eax             ; lpProcName
		56                 push    esi             ; hModule
		FF 15 20 F0 40 00  call    ds:GetProcAddress
		68 A8 0C 41 00     push    offset aLo_adlIbr_arYw; "Lo.adL ibr.ar yW"
		A3 DC 3E 41 00     mov     GetProcAddress_0, eax
		E8 7D FF FF FF     call    CleanupString
		83 C4 04           add     esp, 4
		50                 push    eax             ; _DWORD
		56                 push    esi             ; _DWORD
		FF 15 DC 3E 41 00  call    GetProcAddress_0
		68 94 0C 41 00     push    offset aLoad_LibR_arYa; "Load. Lib r.ar yA"
		A3 D4 3E 41 00     mov     LoadLibraryW, eax
		E8 63 FF FF FF     call    CleanupString
		83 C4 04           add     esp, 4
		50                 push    eax             ; _DWORD
		56                 push    esi             ; _DWORD
		FF 15 DC 3E 41 00  call    GetProcAddress_0
		68 80 0C 41 00     push    offset a_frE_eliBr_arY; ".Fr e.eLi br.ar y"
		A3 D8 3E 41 00     mov     LoadLibraryA_0, eax
		E8 49 FF FF FF     call    CleanupString
	*/

	$a = {
			83 C4 ?? 
			5? 
			5? 
			FF 15 [4]
			68 [4]
			A3 [4]
			E8 [4]
			83 C4 ?? 
			5? 
			5? 
			FF 15 [4]
			68 [4]
			A3 [4]
			E8 [4]
			83 C4 ?? 
			5? 
			5? 
			FF 15 [4]
			68 [4]
			A3 [4]
			E8
		}


	condition:
		$a in ((pe.sections[pe.section_index(".text")].raw_data_offset)..(pe.sections[pe.section_index(".text")].raw_data_offset + pe.sections[pe.section_index(".text")].raw_data_size))
}


rule DNSCalcStyleEncodeAndDecode: sharedcode
{
	meta:
		copyright = "2015 Novetta Solutions"
		author = "Novetta Threat Research & Interdiction Group - trig@novetta.com"
		Source = "975522bc3e07f7aa2c4a5457e6cc16c49a148b9f731134b8971983225835577e"

	strings:
	/*
		8A 10     mov     dl, [eax]
		80 F2 73  xor     dl, 73h					<--- for decoding and encoding, this and
		80 EA 3A  sub     dl, 3Ah					<--- this could be reversed, but the sig holds since both are 0x80
		88 10     mov     [eax], dl
		40        inc     eax
		49        dec     ecx
		75 F2     jnz     short loc_1000403C
	*/

	$a = {
			8A ?? 
			80 ?? ?? 
			80 ?? ?? 
			88 ?? 
			4? 
			4? 
			75 ?? 
		}

	condition:
		$a in ((pe.sections[pe.section_index(".text")].raw_data_offset)..(pe.sections[pe.section_index(".text")].raw_data_offset + pe.sections[pe.section_index(".text")].raw_data_size))
}

rule GenerateTLSClientHelloPacket_Test: sharedcode
{
	meta:
		copyright = "2015 Novetta Solutions"
		author = "Novetta Threat Research & Interdiction Group - trig@novetta.com"
		Source = "eff542ac8e37db48821cb4e5a7d95c044fff27557763de3a891b40ebeb52cc55.ex_"

	strings:
	/*
		25 07 00 00 80  and     eax, 80000007h
		79 05           jns     short loc_405EC8; um, nope.. this will always happen
		48              dec     eax
		83 C8 F8        or      eax, 0FFFFFFF8h
		40              inc     eax
	*/

	$a = {
			25 07 00 00 80 
			79 ?? 
			4? 
			83 ?? F8 
			4? 
		}

	condition:
		$a in ((pe.sections[pe.section_index(".text")].raw_data_offset)..(pe.sections[pe.section_index(".text")].raw_data_offset + pe.sections[pe.section_index(".text")].raw_data_size))
}

rule RC4SboxKeyGen: sharedcode
{
	meta:
		copyright = "2015 Novetta Solutions"
		author = "Novetta Threat Research & Interdiction Group - trig@novetta.com"
		Source = "RT_RCDATA_101.bin.bin"

	strings:
	/*
		8A 4C 04 08        mov     cl, [esp+eax+108h+sbox]; cl = sbox[i]
		8B D0              mov     edx, eax
		81 E2 0F 00 00 80  and     edx, 8000000Fh  ; i % 16
		79 05              jns     short loc_10003AC8; dl = key[i & 16]
		4A                 dec     edx
		83 CA F0           or      edx, 0FFFFFFF0h
		42                 inc     edx
	*/

	$a = {
			8A [3] 
			8B ?? 
			81 ?? 0F 00 00 80 
			79 ?? 
			4? 
			83 ?? F0 
			4? 
		}

	condition:
		$a in ((pe.sections[pe.section_index(".text")].raw_data_offset)..(pe.sections[pe.section_index(".text")].raw_data_offset + pe.sections[pe.section_index(".text")].raw_data_size))
}


rule RandomTimestampGenerator: sharedcode
{
	meta:
		copyright = "2015 Novetta Solutions"
		author = "Novetta Threat Research & Interdiction Group - trig@novetta.com"
		Source = "RT_RCDATA_101.bin.bin joanap baseline sample"

	strings:
	/*
		66 81 44 24 0C FE FF  add     [esp+1Ch+SystemTime.wYear], 0FFFEh
		FF D6                 call    esi ; rand
		99                    cdq
		B9 0C 00 00 00        mov     ecx, 0Ch
		F7 F9                 idiv    ecx
		42                    inc     edx
		66 89 54 24 0E        mov     [esp+1Ch+SystemTime.wMonth], dx
		FF D6                 call    esi ; rand
		99                    cdq
		B9 1C 00 00 00        mov     ecx, 1Ch
		F7 F9                 idiv    ecx
		42                    inc     edx
		66 89 54 24 12        mov     [esp+1Ch+SystemTime.wDay], dx
		FF D6                 call    esi ; rand
		99                    cdq
		B9 17 00 00 00        mov     ecx, 17h
		F7 F9                 idiv    ecx
		42                    inc     edx
		66 89 54 24 14        mov     [esp+1Ch+SystemTime.wHour], dx
		FF D6                 call    esi ; rand
		99                    cdq
		B9 3B 00 00 00        mov     ecx, 3Bh
		F7 F9                 idiv    ecx
		42                    inc     edx
		66 89 54 24 16        mov     [esp+1Ch+SystemTime.wMinute], dx
		FF D6                 call    esi ; rand
		99                    cdq
		B9 3B 00 00 00        mov     ecx, 3Bh
		F7 F9                 idiv    ecx
	*/

	$a = {
			66 81 [3] FE FF 
			FF [1-4] 
			99 
			B9 0C 00 00 00 
			F7 [1-4] 
			42 
			66 89 [3]  
			FF D6 
			99 
			B9 1C 00 00 00 
			F7 [1-4] 
			42 
			66 89 [3] 
			FF D6 
			99 
			B9 17 00 00 00 
			F7 [1-4] 
			42 
			66 89 [3] 
			FF D6 
			99 
			B9 3B 00 00 00 
			F7 [1-4] 
			42 
			66 89 [3] 
			FF D6 
			99 
			B9 3B 00 00 00 
			F7 
		}

	condition:
		$a in ((pe.sections[pe.section_index(".text")].raw_data_offset)..(pe.sections[pe.section_index(".text")].raw_data_offset + pe.sections[pe.section_index(".text")].raw_data_size))
}

rule CPUInfoExtraction
{
	meta:
		copyright = "2015 Novetta Solutions"
		author = "Novetta Threat Research & Interdiction Group - trig@novetta.com"
		Source = "Cmd10010_296fcc9d611ca1b8f8288192d6d854cf4072853010cc65cb0c7f958626999fbd.bin"

	strings:
	/*
		68 00 00 00 80     push    80000000h       ; a2
		8B 02              mov     eax, [edx]
		8B 4A 04           mov     ecx, [edx+4]
		89 4C 24 10        mov     [esp+2Ch+var_1C], ecx
		8B 4A 08           mov     ecx, [edx+8]
		89 4C 24 14        mov     [esp+2Ch+var_18], ecx
		8B 4A 0C           mov     ecx, [edx+0Ch]
		8D 54 24 1C        lea     edx, [esp+2Ch+var_10]
		89 8E 70 03 00 00  mov     [esi+370h], ecx
		52                 push    edx             ; a1
		8B CE              mov     ecx, esi
		89 86 6C 03 00 00  mov     [esi+36Ch], eax
		E8 29 FF FF FF     call    GetCPUIDValues
		8B C8              mov     ecx, eax
		8B 01              mov     eax, [ecx]
		3D 00 00 00 80     cmp     eax, 80000000h
		8B 51 04           mov     edx, [ecx+4]
	*/

	$a = {
			68 00 00 00 80 
			8B ?? 
			8B ?? 04 
			89 [3] 
			8B ?? 08 
			89 [3] 
			8B ?? 0C 
			8D [3] 
			89 [5] 
			5? 
			8B ?? 
			89 [5]
			E8 [4]
			8B ?? 
			8B ?? 
			3D 00 00 00 80 
			8B ?? 04 
		}

	condition:
		$a in ((pe.sections[pe.section_index(".text")].raw_data_offset)..(pe.sections[pe.section_index(".text")].raw_data_offset + pe.sections[pe.section_index(".text")].raw_data_size))
}

import "pe"

rule SierraAlfa
{
	meta:
		copyright = "2015 Novetta Solutions"
		author = "Novetta Threat Research & Interdiction Group - trig@novetta.com"
		Source = "4d4b17ddbcf4ce397f76cf0a2e230c9d513b23065f746a5ee2de74f447be39b9.ex_"

	strings:
	/*
		8D 54 24 08              lea     edx, [esp+128h+argp]
		52                       push    edx             ; argp
		68 7E 66 04 80           push    8004667Eh       ; cmd
		56                       push    esi             ; s
		E8 DB 51 00 00           call    ioctlsocket
		8D 44 24 14              lea     eax, [esp+128h+name]
		6A 10                    push    10h             ; namelen
		50                       push    eax             ; name
		56                       push    esi             ; s
		E8 C8 51 00 00           call    connect
		8B 8C 24 34 01 00 00     mov     ecx, [esp+128h+dwTimeout]
		8D 54 24 0C              lea     edx, [esp+128h+timeout]
		52                       push    edx             ; timeout
		8D 44 24 28              lea     eax, [esp+12Ch+writefds]
		6A 00                    push    0               ; exceptfds
		50                       push    eax             ; writefds
		6A 00                    push    0               ; readfds
		6A 00                    push    0               ; nfds
		89 74 24 3C              mov     [esp+13Ch+writefds.fd_array], esi
		89 7C 24 38              mov     [esp+13Ch+writefds.fd_count], edi
		89 4C 24 20              mov     [esp+13Ch+timeout.tv_sec], ecx
		C7 44 24 24 00 00 00 00  mov     [esp+13Ch+timeout.tv_usec], 0
		E8 92 51 00 00           call    select
		33 C9                    xor     ecx, ecx
		56                       push    esi             ; s
		85 C0                    test    eax, eax
		0F 9F C1                 setnle  cl
		8B F9                    mov     edi, ecx
		E8 7D 51 00 00           call    closesocket
	*/

	$connectTest = { 8D [3] 5? 68 7E 66 04 80 5? E8 [4] 8D [3] 6A 10 5? 5? E8 [4] 8B [6] 8D [3] 5? 8D [3] 6A 00 5? 6A 00 6A 00 
			89 [3] 89 [3] 89 [3] C7 [7] E8 [4] 33 ?? 5? 85 C0 0F 9F ?? 8B ?? E8 }

	/*
		E8 D8 62 00 00                                call    rand
		8B F8                                         mov     edi, eax
		E8 D1 62 00 00                                call    rand
		0F AF F8                                      imul    edi, eax
		E8 C9 62 00 00                                call    rand
		0F AF C7                                      imul    eax, edi
		99                                            cdq
		33 C2                                         xor     eax, edx
		2B C2                                         sub     eax, edx
		33 D2                                         xor     edx, edx
		F7 F6                                         div     esi
		8B FA                                         mov     edi, edx
		57                                            push    edi
		E8 05 13 00 00                                call    sub_402BD0
	*/
	 	$maths = { E8 [4] 8B ?? E8 [4] 0F AF ?? E8 [4] 0F AF ?? 99 33 ?? 2B ?? 33 ?? F7 ?? 8B ?? 5? E8}
		
		$s1 = "recdiscm32.exe"
		$s2 = "\\\\%s\\shared$\\syswow64"
		$s3 = "\\\\%s\\shared$\\system32"

	condition:
		$connectTest in ((pe.sections[pe.section_index(".text")].raw_data_offset)..(pe.sections[pe.section_index(".text")].raw_data_offset + pe.sections[pe.section_index(".text")].raw_data_size))
		or $maths in ((pe.sections[pe.section_index(".text")].raw_data_offset)..(pe.sections[pe.section_index(".text")].raw_data_offset + pe.sections[pe.section_index(".text")].raw_data_size))
		or 3 of ($s*)

}

// Brambul related signatures

import "pe"

rule SierraBravo_Two
{
	meta:
		copyright = "2015 Novetta Solutions"
		author = "Novetta Threat Research & Interdiction Group - trig@novetta.com"

	strings:
		/*
		.text:00403D5A                 mov     word ptr [esi+0Eh], 0C807h
		.text:00403D60                 mov     dword ptr [esi+39h], 800000D4h
		.text:00403D67                 mov     byte ptr [edi], 0Ch							<---- ignored
		.text:00403D6A                 mov     word ptr [esi+25h], 0FFh
		.text:00403D70                 mov     word ptr [esi+27h], 0A4h
		.text:00403D76                 mov     word ptr [esi+29h], 4104h
		.text:00403D7C                 mov     word ptr [esi+2Bh], 32h
		
		or
		
		.text:100036F9                 mov     word ptr [ebx+0Eh], 0C807h
														---- begin ignored -----
		.text:100036FF                 rep movsd
		.text:10003701                 lea     edi, [ebx+60h]
		.text:10003704                 mov     ecx, 9
		.text:10003709                 mov     esi, offset aWindows2000219 ; "windows 2000 2195"
														---- end ignored -----
		.text:1000370E                 mov     dword ptr [ebx+39h], 800000D4h
		.text:10003715                 mov     word ptr [ebx+25h], 0FFh
		.text:1000371B                 mov     word ptr [ebx+27h], 0A4h
		.text:10003721                 mov     word ptr [ebx+29h], 4104h
		.text:10003727                 mov     word ptr [ebx+2Bh], 32h
		*/
		$smbComNegotiationPacketGen = { 66 C7 ?? 0E 07 C8 
																		[0-32]
																		C7 ?? 39 D4 00 00 80 
																		[0-32]
																		66 C7 ?? 25 FF 00 
																		[0-32]
																		66 C7 ?? 27 A4 00 
																		[0-32]
																		66 C7 ?? 29 04 41 
																		[0-32]
																		66 C7 ?? 2B 32 00
																	}

		$lib = "!emCFgv7Xc8ItaVGN0bMf"
		$api1 = "!ctRHFEX5m9JnZdDfpK"
		$api2 = "!emCFgv7Xc8ItaVGN0bMf"
		$api3 = "!VWBeBxYx1nzrCkBLGQO"		
		$pwd = "iamsorry!@1234567"										

		
	condition:
		$smbComNegotiationPacketGen in ((pe.sections[pe.section_index(".text")].raw_data_offset)..(pe.sections[pe.section_index(".text")].raw_data_offset + pe.sections[pe.section_index(".text")].raw_data_size))
		or ($pwd in ((pe.sections[pe.section_index(".data")].raw_data_offset)..(pe.sections[pe.section_index(".data")].raw_data_offset + pe.sections[pe.section_index(".data")].raw_data_size))
		 		and 
		 		($lib in ((pe.sections[pe.section_index(".data")].raw_data_offset)..(pe.sections[pe.section_index(".data")].raw_data_offset + pe.sections[pe.section_index(".data")].raw_data_size))
				or $api1 in ((pe.sections[pe.section_index(".data")].raw_data_offset)..(pe.sections[pe.section_index(".data")].raw_data_offset + pe.sections[pe.section_index(".data")].raw_data_size))
				or $api2 in ((pe.sections[pe.section_index(".data")].raw_data_offset)..(pe.sections[pe.section_index(".data")].raw_data_offset + pe.sections[pe.section_index(".data")].raw_data_size))
				or $api3 in ((pe.sections[pe.section_index(".data")].raw_data_offset)..(pe.sections[pe.section_index(".data")].raw_data_offset + pe.sections[pe.section_index(".data")].raw_data_size))
		))

}


rule SierraBravo_One
{
	meta:
		copyright = "2015 Novetta Solutions"
		author = "Novetta Threat Research & Interdiction Group - trig@novetta.com"

	strings:
		/*
			.text:00402A65                 push    8004667Eh       ; cmd
			.text:00402A6A                 push    esi             ; s
			.text:00402A6B                 call    ioctlsocket
			.text:00402A70                 push    32h             ; dwMilliseconds
			.text:00402A72                 mov     [esp+24Ch+writefds.fd_array], esi
			.text:00402A79                 mov     [esp+24Ch+writefds.fd_count], 1
			.text:00402A84                 mov     [esp+24Ch+timeout.tv_sec], 3
			.text:00402A8C                 mov     [esp+24Ch+timeout.tv_usec], 0			
		*/
		$spreaderSetup = {68 7E 66 04 80 
											5? 
											E8 [4] 
											6A 32 
											89 B4 [5]
											C7 84 [5] 01 00 00 00 
											C7 44 [2] 03 00 00 00 
											C7 44 [2] 00 00 00 00 }

	condition:
		$spreaderSetup in ((pe.sections[pe.section_index(".text")].raw_data_offset)..(pe.sections[pe.section_index(".text")].raw_data_offset + pe.sections[pe.section_index(".text")].raw_data_size))
}

rule SierraBravo_packed
{
	meta:
		copyright = "2015 Novetta Solutions"
		author = "Novetta Threat Research & Interdiction Group - trig@novetta.com"

	strings:
		$ = "cmd.exe /c \"net share admin$ /d\""
		$ = "MAIL FROM:<"
		$ = ".petite"
		$ = "Subject: %s|%s|%s"
	condition:
		3 of them
	
}


import "pe"

rule SierraCharlie
{
	meta:
		copyright = "2015 Novetta Solutions"
		author = "Novetta Threat Research & Interdiction Group - trig@novetta.com"
		Source = "f4750e1d82b08318bdc1eb6d3399dee52750250f7959a5e4f83245449f399698.bin"

	strings:
	/*
		8B 0D 50 A7 56 00  mov     ecx, DnsFree
		81 F6 8C 3F 7C 5E  xor     esi, 5E7C3F8Ch
		6A 01              push    1               ; _DWORD
		50                 push    eax             ; _DWORD
		85 C9              test    ecx, ecx
		74 3A              jz      short loc_40580B
		FF D1              call    ecx ; DnsFree
	*/

	$dnsResolve = {
			8B 0D 50 A7 56 00 
			81 F6 8C 3F 7C 5E 
			6A 01 
			50 
			85 C9 
			74 3A 
			FF D1 
		}
		
	$file1 = "wmplog21t.sqm"
	$file2 = "wmplog15r.sqm"
	$file3 = "wmplog09c.sqm"
		

	condition:
		$dnsResolve in ((pe.sections[pe.section_index(".text")].raw_data_offset)..(pe.sections[pe.section_index(".text")].raw_data_offset + pe.sections[pe.section_index(".text")].raw_data_size))
		or 2 of ($file*)
}


import "pe"

rule SierraJuliettMikeOne
{
	meta:
		copyright = "2015 Novetta Solutions"
		author = "Novetta Threat Research & Interdiction Group - trig@novetta.com"

	strings:
		$commKey = { 10 20 30 40 50 60 70 80 90 11 12 13 1A FF EE 48 }
		/*
		.text:10001850                 push    7530h           ; dwTimeout
		.text:10001855                 lea     eax, [esp+420h+a2]
		.text:10001859                 push    4               ; len
		.text:1000185B                 push    eax             ; a2
		.text:1000185C                 push    esi             ; s
		.text:1000185D                 mov     dword ptr [esp+42Ch+a2], 1000h
		.text:10001865                 call    CommSendWithTimeout
		.text:1000186A                 add     esp, 14h
		.text:1000186D                 cmp     eax, 0FFFFFFFFh
		.text:10001870                 jz      loc_10001915
		.text:10001876                 lea     ecx, [esp+418h+random]
		.text:1000187A                 push    ecx             ; a1
		.text:1000187B                 call    Generate16ByteRandomBuffer
		.text:10001880                 push    0               ; fEncrypt
		.text:10001882                 push    7530h           ; dwTimeout		
		*/
		$handshake = { 68 30 75 00 00 [4] 6A 04 5? 5? C? [3] 00 10 00 00 E8 [7] 83 F8 FF 0F 84 ?? ?? 00 00 8? [3] 5? E8 [4] 6A 00 68 30 75 00 00 }
		
	condition:
		$commKey in ((pe.sections[pe.section_index(".data")].raw_data_offset)..(pe.sections[pe.section_index(".data")].raw_data_offset + pe.sections[pe.section_index(".data")].raw_data_size))
		and $handshake in ((pe.sections[pe.section_index(".text")].raw_data_offset)..(pe.sections[pe.section_index(".text")].raw_data_offset + pe.sections[pe.section_index(".text")].raw_data_size))

}


import "pe"


rule RomeoJuliettMikeTwo
{
	meta:
		copyright = "2015 Novetta Solutions"
		author = "Novetta Threat Research & Interdiction Group - trig@novetta.com"
		Source = "819722ba1c5b9d0b360c54cbdd3811d0cac1a9230720b3ed4815f78bcacb3653_d1ba9ba2987f59d99ce4bf09393c0521c4d1f2961c5aeed4e0bf86e78303d27c"

	strings:
	/*
		81 7C 24 24 33 27 00 00  cmp     [esp+1Ch+dwBytesToRead], 2733h
		75 7F                    jnz     short loc_10002B74
		8D 54 24 14              lea     edx, [esp+1Ch+var_8]
		52                       push    edx             ; Time
		FF 15 5C 11 02 10        call    ds:time
		8B 44 24 14              mov     eax, [esp+20h+var_C]
		83 C4 04                 add     esp, 4
		8B C8                    mov     ecx, eax
		40                       inc     eax
		83 F9 64                 cmp     ecx, 64h
	*/

	$recvFunc = { 81 [3] 33 27 00 00 75 ?? 8D [3] 5? FF 15 [4] 8B [3] 83 ?? 04 8B ?? 4? 83 ?? 64 }

	/*
		E8 74 31 00 00     call    GetStringByIndex
		8B 7C 24 14        mov     edi, [esp+0Ch+dwFuncIndex]
		8B F0              mov     esi, eax
		57                 push    edi             ; index
		E8 68 31 00 00     call    GetStringByIndex
		83 C4 08           add     esp, 8
		85 F6              test    esi, esi
		74 21              jz      short loc_10001040
		85 C0              test    eax, eax
		74 1D              jz      short loc_10001040
		56                 push    esi             ; lpLibFileName
		FF 15 2C 10 02 10  call    ds:LoadLibraryA
		57                 push    edi             ; index
		8B F0              mov     esi, eax
		E8 4E 31 00 00     call    GetStringByIndex
		83 C4 04           add     esp, 4
		50                 push    eax             ; lpProcName
		56                 push    esi             ; hModule
		FF 15 5C 10 02 10  call    ds:GetProcAddress
	*/

	$apiLoader = { E8 [4] 8B [3] 8B ?? 5? E8 [4] 83 C4 08 85 ?? 74 ?? 85 C0 74 ?? 5? FF 15 [4] 5? 8B ?? E8 [4] 83 C4 04 5? 5? FF 15 }

	/*
		68 B8 0B 00 00           push    0BB8h           ; dwMilliseconds
		FF 15 18 10 02 10        call    ds:Sleep
		6A 01                    push    1               ; dwTimeout
		8D 4C 24 10              lea     ecx, [esp+4C0h+peerEntries]
		68 B0 04 00 00           push    4B0h            ; dwBytesToRead
		51                       push    ecx             ; pvRecvBuffer
		8B CE                    mov     ecx, esi        ; this
		C7 44 24 14 B0 04 00 00  mov     [esp+4C8h+Memory], 4B0h
		E8 25 F4 FF FF           call    CClientConnection__RecvData
		83 F8 FF                 cmp     eax, 0FFFFFFFFh
	*/

	$recvPeers = { 68 B8 0B 00 00 FF 15 [4] 6A 01 [0-4] 68 B0 04 00 00 51 8B ?? [1-4] B0 04 00 00 E8 [4] 83 F8 FF	}		
		
	$logFileName = "KBD_%%s_%%02d%%02d%%02d%%02d%%02d.CAT"
	
	condition:
		$recvFunc in ((pe.sections[pe.section_index(".text")].raw_data_offset)..(pe.sections[pe.section_index(".text")].raw_data_offset + pe.sections[pe.section_index(".text")].raw_data_size))
		or $apiLoader in ((pe.sections[pe.section_index(".text")].raw_data_offset)..(pe.sections[pe.section_index(".text")].raw_data_offset + pe.sections[pe.section_index(".text")].raw_data_size))
		or $recvPeers in ((pe.sections[pe.section_index(".text")].raw_data_offset)..(pe.sections[pe.section_index(".text")].raw_data_offset + pe.sections[pe.section_index(".text")].raw_data_size))
		or $logFileName
}


// yara sigs for detecting common suicide scripts

rule SuicideScriptL1
{
	meta:
		copyright = "2015 Novetta Solutions"
		author = "Novetta Threat Research & Interdiction Group - trig@novetta.com"

	strings:
		$ = ":L1\ndel \"%s\"\nif exist \"%s\" goto L1\ndel \"%s\"\n"
	condition:
		any of them
}

rule SuicideScriptR1_Multi
{
	meta:
		copyright = "2015 Novetta Solutions"
		author = "Novetta Threat Research & Interdiction Group - trig@novetta.com"
	
	strings:
		$ = "\" goto R1\ndel /a \""
		$ = "\"\nif exist \""
		$ = "@echo off\n:R1\ndel /a \""
	condition:
		all of them
}

rule SuicideScriptR
{
	// joanap, joanapCleaner
	meta:
		copyright = "2015 Novetta Solutions"
		author = "Novetta Threat Research & Interdiction Group - trig@novetta.com"

	strings:
		$ = ":R\nIF NOT EXIST %s GOTO E\ndel /a %s\nGOTO R\n:E\ndel /a d.bat"
		
	condition:
		all of them

}

rule TangoAlfa
{
	meta:
		copyright = "2015 Novetta Solutions"
		author = "Novetta Threat Research & Interdiction Group - trig@novetta.com"

	strings:
		// $firewall is a shared code string
		$firewall = "%sd.e%sc n%ssh%srewa%s ad%s po%sop%sing T%s %d \"%s\""
		
		$testStatus1 = "*****[Start Test -> %s:%d]" wide
		$testStatus2 = "*****[Relay Connect " wide
		$testStatus3 = "*****[Listen Port %d] - " wide
		$testStatus4 = "*****[Error Socket]" wide
		$testStatus5 = "*****[End Test]" wide

	condition:
		2 of them
}

import "pe"

rule TangoBravo
{
	meta:
		copyright = "2015 Novetta Solutions"
		author = "Novetta Threat Research & Interdiction Group - trig@novetta.com"
		Source = "2aa9cd3a2db2bd9dbe5ee36d9a5fc42b50beca806f9d644f387d5a680a580896"

	strings:
	/*
		50                 push    eax             ; SubStr
		55                 push    ebp             ; Str
		FF D3              call    ebx ; strstr
		83 C4 08           add     esp, 8
		85 C0              test    eax, eax
		75 1A              jnz     short loc_401131
		8A 8E 08 01 00 00  mov     cl, [esi+108h]
		81 C6 08 01 00 00  add     esi, 108h
		47                 inc     edi
		8B C6              mov     eax, esi
		84 C9              test    cl, cl
		75 E2              jnz     short loc_40110C
	*/

	$targetDomainCheck = {
			5? 
			5? 
			FF ?? 
			83 C4 08 
			85 C0 
			75 ?? 
			8? ?? 08 01 00 00 
			8? ?? 08 01 00 00 
			4? 
			8B ?? 
			84 ?? 
			75  
		}

	condition:
		$targetDomainCheck in ((pe.sections[pe.section_index(".text")].raw_data_offset)..(pe.sections[pe.section_index(".text")].raw_data_offset + pe.sections[pe.section_index(".text")].raw_data_size))
}


import "pe"

rule UniformAlfa
{
	meta:
		copyright = "2015 Novetta Solutions"
		author = "Novetta Threat Research & Interdiction Group - trig@novetta.com"
		Source = "a24377681cf56c712e544af01ac8a5dbaa81d16851a17a147bbf5132890d7437"

	strings:
	/*
		8D 44 24 10        lea     eax, [esp+2Ch+ServiceStatus]
		50                 push    eax             ; lpServiceStatus
		6A 01              push    1               ; dwControl
		56                 push    esi             ; hService
		FF D3              call    ebx ; ControlService
		83 7C 24 14 01     cmp     [esp+2Ch+ServiceStatus.dwCurrentState], 1
		75 EF              jnz     short loc_4010A5
		56                 push    esi             ; hService
		FF 15 08 70 40 00  call    ds:DeleteService
	*/

	$stopDeleteService = {
			8D [3] 
			5? 
			6A 01 
			5? 
			FF D? 
			83 [3] 01 
			75 ?? 
			5? 
			FF 15  
		}

	condition:
		$stopDeleteService in ((pe.sections[pe.section_index(".text")].raw_data_offset)..(pe.sections[pe.section_index(".text")].raw_data_offset + pe.sections[pe.section_index(".text")].raw_data_size))
}


rule UniformJuliett
{
	meta:
		copyright = "2015 Novetta Solutions"
		author = "Novetta Threat Research & Interdiction Group - trig@novetta.com"
		Source = "Cmd03000_1a6f62e1630d512c3b67bfdbff26270177585c82802ffa834b768ff47be0a008.bin"

	strings:
		/*
			56                 push    esi             ; hSCObject
			FF D5              call    ebp ; CloseServiceHandle
			68 B8 0B 00 00     push    0BB8h           ; dwMilliseconds
			FF 15 38 70 40 00  call    ds:Sleep
			6A 00              push    0               ; fCreateHighestLevel
			68 60 A9 40 00     push    offset PathName ; lpPathName
			E8 43 FE FF FF     call    RecursivelyCreateDirectories
			83 C4 08           add     esp, 8
			68 60 A9 40 00     push    offset PathName ; lpFileName
			FF 15 3C 70 40 00  call    ds:DeleteFileA
		*/
		
		$a = {
				56 
				FF D5 
				68 B8 0B 00 00 
				FF 15 [4] 
				6A 00 
				68 [4]
				E8 [4]
				83 C4 08 
				68 [4]
				FF 15 
			}
		
		$ = "wauserv.dll"
		$ = "Rpcss"
	
	condition:
		all of them
}


import "pe"

rule WhiskeyAlfa
{
	meta:
		copyright = "2015 Novetta Solutions"
		author = "Novetta Threat Research & Interdiction Group - trig@novetta.com"
		Source = "1c66e67a8531e3ff1c64ae57e6edfde7bef2352d.ex_"

	strings:
	/*
		E8 77 07 00 00     call    _rand
		B1 FB              mov     cl, 0FBh
		F6 E9              imul    cl
		88 44 34 08        mov     [esp+esi+10008h+randomData], al
		46                 inc     esi
		81 FE 00 00 01 00  cmp     esi, 10000h
		7C EA              jl      short loc_402E8D
	*/

	$randomBuffer = {
			E8 [4] 
			B1 ?? 
			F6 E9 
			88 [3] 
			4? 
			81 ?? 00 00 01 00 
			7C  
		}

	/*
		89 58 09              mov     [eax+9], ebx
		C7 40 65 00 00 02 00  mov     dword ptr [eax+65h], 20000h
		C7 40 15 04 00 00 00  mov     dword ptr [eax+15h], 4
		C6 40 08 08           mov     byte ptr [eax+8], 8
		C7 40 04 00 02 00 00  mov     dword ptr [eax+4], 200h
		89 18                 mov     [eax], ebx
		89 58 0D              mov     [eax+0Dh], ebx
		C7 40 11 01 00 00 00  mov     dword ptr [eax+11h], 1
		89 58 69              mov     [eax+69h], ebx
		89 58 19              mov     [eax+19h], ebx
		B8 01 00 00 00        mov     eax, 1
	*/
	$mbrDiskInfo = {
			89 ?? 09 
			C7 ?? 65 00 00 02 00 
			C7 ?? 15 04 00 00 00 
			C6 ?? 08 08 
			C7 ?? 04 00 02 00 00 
			89 ?? 
			89 ?? 0D
			C7 ?? 11 01 00 00 00 
			89 ?? 69 
			89 ?? 19 
			B8 01 00 00 00 
		}
		

		// the replacement MBRs in both encoded (XOR 0x53) and decoded form		
		$mbrReplacement_Decoded = { B4 43 B0 00 CD 13 FE C2 80 FA 84 7C F3 B2 80 BF 65 7C 81 05 00 04 83 55 02 00 83 55 04 00 }
		$mbrReplacement_Encoded = { E7 10 E3 53 9E 40 AD 91 D3 A9 D7 2F A0 E1 D3 EC 36 2F D2 56 53 57 D0 06 51 53 D0 06 57 53 }
	
		$licKey = "99E2428CCA4309C68AAF8C616EF3306582A64513E55C786A864BC83DAFE0C78585B692047273B0E55275102C664C5217E76B8E67F35FCE385E4328EE1AD139EA6AA26345C4F93000DBBC7EF1579D4F"
		
	condition:
		$licKey or $mbrReplacement_Decoded or $mbrReplacement_Encoded
		or $randomBuffer in ((pe.sections[pe.section_index(".text")].raw_data_offset)..(pe.sections[pe.section_index(".text")].raw_data_offset + pe.sections[pe.section_index(".text")].raw_data_size))
		or $mbrDiskInfo in ((pe.sections[pe.section_index(".text")].raw_data_offset)..(pe.sections[pe.section_index(".text")].raw_data_offset + pe.sections[pe.section_index(".text")].raw_data_size))
}


import "pe"

rule WhiskeyBravo
{
	meta:
		copyright = "2015 Novetta Solutions"
		author = "Novetta Threat Research & Interdiction Group - trig@novetta.com"
		Source = "74eac0461c40316689ac2d598f606caa3965195b22f23d5acefeedfcdf056c5b"
		Source = "41badf10ef6f469dd1c3be201aba809f9c42f86ad77d7f83bc3895bfa289c635"
		Source = "d079a266ed2a852c33cdac3df115d163ebbf2c8dae32d935e895cf8193163b13"

	strings:
	/*
		6A 04              push    4               ; MaxCount  <--- this arg is not found in some variants (41bad..) as wcscmp is used instead
		68 08 82 00 10     push    offset Str2     ; ".doc"
		56                 push    esi             ; Str1
		FF D7              call    edi ; _wcsnicmp            <--- d07... variant uses a direct call instead
		83 C4 0C           add     esp, 0Ch										<--- when wcscmp is used, this is add esp, 8
		85 C0              test    eax, eax
		0F 84 5B 02 00 00  jz      loc_100017D5
		6A 05              push    5               ; MaxCount
		68 FC 81 00 10     push    offset a_docx   ; ".docx"
		56                 push    esi             ; Str1
		FF D7              call    edi ; _wcsnicmp
		83 C4 0C           add     esp, 0Ch
		85 C0              test    eax, eax
		0F 84 46 02 00 00  jz      loc_100017D5
		6A 04              push    4               ; MaxCount
		68 F0 81 00 10     push    offset a_docm   ; ".docm"
		56                 push    esi             ; Str1
		FF D7              call    edi ; _wcsnicmp
		83 C4 0C           add     esp, 0Ch
		85 C0              test    eax, eax
		0F 84 31 02 00 00  jz      loc_100017D5
		6A 04              push    4               ; MaxCount
		68 E4 81 00 10     push    offset a_wpd    ; ".wpd"
		56                 push    esi             ; Str1
		FF D7              call    edi ; _wcsnicmp
	*/

	$a = {68 [4] 5? FF D? 83 C4 0C 85 C0 0F 84 [4] [0-2] 68 [4] 5? FF D? 83 C4 0C 85 C0 0F 84 [4] [0-2] 68 [4] 5? FF D? 83 C4 0C 85 C0 0F 84 }

	$ext1 = ".wpd" wide nocase
	$ext2 = ".doc" wide nocase
	$ext3 = ".hwp" wide nocase
	
	condition:
		2 of ($ext*) and $a in ((pe.sections[pe.section_index(".text")].raw_data_offset)..(pe.sections[pe.section_index(".text")].raw_data_offset + pe.sections[pe.section_index(".text")].raw_data_size))
}

import "pe"

rule WhiskeyCharlie
{
	meta:
		copyright = "2015 Novetta Solutions"
		author = "Novetta Threat Research & Interdiction Group - trig@novetta.com"
		Source = "47ff4f73738acc2f8433dccb2caf980d7444d723ccf2968d69f88f8f96405f96"

	strings:
	/*
		66 89 55 DC     mov     [ebp+SystemTime.wYear], dx
		E8 1E 16 00 00  call    _rand
		6A 0C           push    0Ch
		99              cdq
		59              pop     ecx
		F7 F9           idiv    ecx
		42              inc     edx
		66 89 55 DE     mov     [ebp+SystemTime.wMonth], dx
		E8 0E 16 00 00  call    _rand
		6A 1C           push    1Ch
		99              cdq
		59              pop     ecx
		F7 F9           idiv    ecx
		42              inc     edx
		66 89 55 E2     mov     [ebp+SystemTime.wDay], dx
		E8 FE 15 00 00  call    _rand
		6A 18           push    18h
		99              cdq
		59              pop     ecx
		F7 F9           idiv    ecx
		66 89 55 E4     mov     [ebp+SystemTime.wHour], dx
		E8 EF 15 00 00  call    _rand
		6A 3C           push    3Ch
		99              cdq
		59              pop     ecx
		F7 F9           idiv    ecx
		66 89 55 E6     mov     [ebp+SystemTime.wMinute], dx
		E8 E0 15 00 00  call    _rand
		6A 3C           push    3Ch
		99              cdq
		59              pop     ecx
		F7 F9           idiv    ecx
	*/

	$a = {
			66 89 55 DC 
			E8 [4] 
			6A 0C 
			99 
			59 
			F7 F9 
			42 
			66 89 55 DE 
			E8 [4] 
			6A 1C 
			99 
			59 
			F7 F9 
			42 
			66 89 55 E2 
			E8 [4] 
			6A 18 
			99 
			59 
			F7 F9 
			66 89 55 E4 
			E8 [4] 
			6A 3C 
			99 
			59 
			F7 F9 
			66 89 55 E6 
			E8 [4] 
			6A 3C 
			99 
			59 
			F7 F9 
		}

	condition:
		$a in ((pe.sections[pe.section_index(".text")].raw_data_offset)..(pe.sections[pe.section_index(".text")].raw_data_offset + pe.sections[pe.section_index(".text")].raw_data_size))
}

import "pe"

rule WhiskeyDelta
{
	meta:
		copyright = "2015 Novetta Solutions"
		author = "Novetta Threat Research & Interdiction Group  trig@novetta.com"
		Source = "41badf10ef6f469dd1c3be201aba809f9c42f86ad77d7f83bc3895bfa289c635"

	strings:
	/*
		F3 A5           rep movsd
		8B 7C 24 30     mov     edi, [esp+28h+arg_4]
		85 FF           test    edi, edi
		7E 3A           jle     short loc_402018
		8B 74 24 2C     mov     esi, [esp+28h+arg_0]
		8A 44 24 08     mov     al, [esp+28h+var_20]
		53              push    ebx
		8A 4C 24 21     mov     cl, [esp+2Ch+var_B]
		8A 5C 24 2B     mov     bl, [esp+2Ch+var_1]
		32 C1           xor     al, cl
		8A 0C 32        mov     cl, [edx+esi]
		32 C3           xor     al, bl
		32 C8           xor     cl, al
		88 0C 32        mov     [edx+esi], cl
		B9 1E 00 00 00  mov     ecx, 1Eh
		8A 5C 0C 0C     mov     bl, [esp+ecx+2Ch+var_20]
		88 5C 0C 0D     mov     [esp+ecx+2Ch+var_1F], bl
		49              dec     ecx
		83 F9 FF        cmp     ecx, 0FFFFFFFFh
		7F F2           jg      short loc_402000
		42              inc     edx
	*/

	$decryption = {
			F3 A5 
			8B 7C 24 30 
			85 FF 
			7E ?? 
			8B 74 24 2C 
			8A 44 24 08 
			53 
			8A 4C 24 21 
			8A 5C 24 2B 
			32 C1 
			8A 0C 32 
			32 C3 
			32 C8 
			88 0C 32 
			B9 1E 00 00 00 
			8A 5C 0C 0C 
			88 5C 0C 0D 
			49 
			83 F9 FF 
			7F ?? 
			42 
		}

	$s1 = "=====IsFile=====" wide
	$s2 = "=====4M=====" wide
	$s3 = "=====IsBackup=====" wide
	
	condition:
		2 of ($s*) 
		or $decryption in ((pe.sections[pe.section_index(".text")].raw_data_offset)..(pe.sections[pe.section_index(".text")].raw_data_offset + pe.sections[pe.section_index(".text")].raw_data_size))
}

rule zox
{
	meta:
		Author = "Novetta"
		Reference = "https://www.novetta.com/wp-content/uploads/2014/11/ZoxPNG.pdf"

	strings:
		$url ="png&w=800&h=600&ei=CnJcUcSBL4rFkQX444HYCw&zoom=1&ved=1t:3588,r:1,s:0,i:92&iact=rc&dur=368&page=1&tbnh=184&tbnw=259&start=0&ndsp=20&tx=114&ty=58"

	condition:
		$url
}