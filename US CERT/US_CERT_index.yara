import "pe"
rule Destructive_Hard_Drive_Tool

{
	meta:
		author = "US CERT"
		reference = "https://www.us-cert.gov/ncas/alerts/TA14-353A"

	strings:

		$str0= "MZ"

		$str1 = {c6 84 24 ?? ( 00 | 01 ) 00 00 }

		$xorInLoop = { 83 EC 20 B9 08 00 00 00 33 D2 56 8B 74 24 30 57 8D 7C 24 08 F3 A5 8B 7C 24 30 85 FF 7E 3A 8B 74 24 2C 8A 44 24 08 53 8A 4C 24 21 8A 5C 24 2B 32 C1 8A 0C 32 32 C3 32 C8 88 0C 32 B9 1E 00 00 00 8A 5C 0C 0C 88 5C 0C 0D 49 83 F9 FF 7F F2 42 88 44 24 0C 3B D7 7C D0 5B 5F 5E 83 C4 20 C3 }

	condition:

		$str0 at 0 and $xorInLoop and #str1 > 300

}
/*
rule Destructive_Target_Cleaning_Tool
{
	meta:
		author = "US CERT"
		reference = "https://www.us-cert.gov/ncas/alerts/TA14-353A"

	strings:
		$s1  = {d3000000 [4] 2c000000 [12] 95000000 [4] 6a000000 [8] 07000000}

	condition:
		(uint16(0) == 0x5A4D and uint16(uint32(0x3c)) == 0x4550) and all of them

}
*/


rule Destructive_Target_Cleaning_Tool_2

{
	meta:
		author = "US CERT"
		reference = "https://www.us-cert.gov/ncas/alerts/TA14-353A"
        
	strings:

		$secureWipe= "{ 83 EC 34 53 55 8B 6C 24 40 56 57 83 CE FF 55 C7 44 24 2C D3 00 00 00 C7 44 24 30 2C 00 00 00 89 74 24 34 89 74 24 38 C7 44 24 3C 95 00 00 00 C7 44 24 40 6A 00 00 00 89 74 24 44 C7 44 24 14 07 00 00 00 FF 15 ?? ?? ?? ?? 3B C6 89 44 24 1C 0F 84 (D8 | d9) 01 00 00 33 FF 68 00 00 01 00 57 FF 15 ?? ?? ?? ?? 8B D8 3B DF 89 5C 24 14 0F 84 (BC | BD) 01 00 00 8B 44 24 1C A8 01 74 0A 24 FE 50 55 FF 15 ?? ?? ?? ?? 8B 44 24 4C 2B C7 74 20 48 74 0F 83 E8 02 75 1C C7 44 24 10 03 00 00 00 EB 12 C7 44 24 10 01 00 00 00 89 74 24 28 EB 04 89 7C 24 10 8B 44 24 10 89 7C 24 1C 3B C7 0F 8E ( 5C | 5d ) 01 00 00 8D 44 24 28 89 44 24 4C EB 03 83 CE FF 8B 4C 24 4C 8B 01 3B C6 74 17 8A D0 B9 00 40 00 00 8A F2 8B FB 8B C2 C1 E0 10 66 8B C2 F3 AB EB ( 13 | 14) 33 F6 (E8 | ff 15) ?? ?? ?? ?? 88 04 1E 46 81 FE 00 00 01 00 7C ( EF | ee) 6A 00 6A 00 6A 03 6A 00 6A 03 68 00 00 00 C0 55 FF 15 ?? ?? ?? ?? 8B F0 83 FE FF 0F 84 FA 00 00 00 8D 44 24 20 50 56 FF 15 ?? ?? ?? ?? 8B 2D ?? ?? ?? ?? 6A 02 6A 00 6A FF 56 FF D5 8D 4C 24 18 6A 00 51 6A 01 53 56 FF 15 ?? ?? ?? ?? 56 FF 15 ?? ?? ?? ?? 6A 00 6A 00 6A 00 56 FF D5 8B 44 24 24 8B 54 24 20 33 FF 33 DB 85 CO 7C 5A 7F 0A 85 D2 76 54 EB 04 8B 54 24 20 8B CA BD 00 00 01 00 2B CF 1B C3 85 C0 7F 0A 7C 04 3B CD 73 04 2B D7 8B EA 8B 44 24 14 8D 54 24 18 6A 00 52 55 50 56 FF 15 ?? ?? ?? ?? 8B 6C 24 18 8B 44 24 24 03 FD 83 D3 00 3B D8 7C BE 7F 08 8B 54 24 20 3B FA 72 B8 8B 2D ?? ?? ?? ?? 8B 5C 24 10 8B 7C 24 1C 8D 4B FF 3B F9 75 17 56 FF 15 ?? ?? ?? ?? 6A 00 6A 00 6A 00 56 FF D5 56 FF 15 ?? ?? ?? ?? 56 FF 15 ?? ?? ?? ?? 56 FF 15 ?? ?? ?? ?? 8B 4C 24 4C 8B 6C 24 48 47 83 C1 04 3B FB 8B 5C 24 14 89 7C 24 1C 89 4C 24 4C 0F 8C ( AE | AD) FE FF FF 6A 00 55 E8 ?? ?? ?? ?? 83 C4 08 53 FF 15 ?? ?? ?? ?? 5F 5E 5D 5B 83 C4 34 C3}"

	condition:

		$secureWipe
}

rule Destructive_Target_Cleaning_Tool_3

{
	meta:
		author = "US CERT"
		reference = "https://www.us-cert.gov/ncas/alerts/TA14-353A"

	strings:

		$S1_CMD_Arg = "/install" fullword
		//$S2_CMD_Parse= ""\""%s'"'  /install \""%s\""'"' fullword
		//$S3_CMD_Builder= ""\'"'%s\""  \""%s\'"' \""%s\'"' %s'"' fullword

condition:

all of them
}
/*
rule Destructive_Target_Cleaning_Tool_4:
{
	meta:
		author = "US CERT"
		reference = "https://www.us-cert.gov/ncas/alerts/TA14-353A"
	
	strings:
		$BATCH_SCRIPT_LN1_0 = "goto x" fullword
		$BATCH_SCRIPT_LN1_1 = "del" fullword
		$BATCH_SCRIPT_LN2_0 = "if exist" fullword
		$BATCH_SCRIPT_LN3_0 = ":x" fullword
		$BATCH_SCRIPT_LN4_0 = "zz%d.bat" fullword

	condition:
		(#BATCH_SCRIPT_LNl_l == 2) and all of them"
}

*/

rule Destructive_Target_Cleaning_Tool_5

{
	meta:
		author = "US CERT"
		reference = "https://www.us-cert.gov/ncas/alerts/TA14-353A"
	
    strings:
		$MCU_DLL_ZLIB_COMPRESSED2= "{5CECABAE813CC9BCD5A542F454910428343479806F71D5521E2AOD}"

	condition:
		all of them
}


rule Destructive_Target_Cleaning_Tool_6

{
	meta:
    
		author = "US CERT"
		reference = "https://www.us-cert.gov/ncas/alerts/TA14-353A"

	strings:

		$MCU_INF_StartHexDec = "{010346080A30D63633000B6263750A5052322A00103D1B570A30E67F2A00130952690A50 3A0D2A000E00A26El5104556766572636C7669642E657865}"

		$MCU_INF_StartHexEnc = "{6C3272386958BF075230780A0A54676166024968790C7A6779588F5E47312739310163615B3D59686721CF5F2120263ElF5413531FlE004543544C55}"

condition:

$MCU_INF_StartHexEnc or $MCU_INF_StartHexDec

}

rule Destructive_Target_Cleaning_Tool_7

{
	meta:
		author = "US CERT"
		reference = "https://www.us-cert.gov/ncas/alerts/TA14-353A"

	strings:
		$ = "SetFilePointer"
		$ = "SetEndOfFile"
		$ = "{75 17 56 ff 15 ?? ?? ?? ?? 6a 00 6a 00 6a 00 56 ffD5 56 ff 15?? ?? ?? ?? 56}"

	condition:
		(uint16(0) == 0x5A4D and uint16(uint32(0x3c)) == 0x4550) and all of them
}

rule Destructive_Target_Cleaning_Tool_8

{
	meta:
		author = "US CERT"
		reference = "https://www.us-cert.gov/ncas/alerts/TA14-353A"
	
	strings:
		$license= "{E903FFFF820050006F007200740069006F006E007300200063006F007000790072006900670068007400200052006F006200650072007400200064006500200042006100740068002C0020004A006F007200690073002000760061006E002000520061006E007400770069006A006B002C002000440065006C00690061006E000000000000000250000000000A002200CE000800EA03FFFF8200}"
		$PuTTY= "{50007500540054005900}"

	condition:
		(uint16(0) == 0x5A4D and uint16(uint32(0x3c)) == 0x4550) and $license and not $PuTTY
 }
 
rule Lightweight_Backdoor

{
    meta:
		author = "US CERT"
		reference = "https://www.us-cert.gov/ncas/alerts/TA14-353A"

    strings:
	    $STR1 = "NetMgStart"
		$STR2 = "Netmgmt.srg"

	condition:
    	(uint16(0) == 0x5A4D) and all of them
        }
        
rule Lightweight_Backdoor_2

{

	meta:
		author = "US CERT"
		reference = "https://www.us-cert.gov/ncas/alerts/TA14-353A"

	strings:
		$STR1 = "prxTroy" ascii wide nocase

	condition:
		(uint16(0) == 0x5A4D or uint16(0) == 0xCFD0 or uint16(0) == 0xC3D4 or uint32(0) == 0x46445025 or uint32(1) == 0x6674725C) and all of them

}

rule Lightweight_Backdoor_3

{

	meta:
		author = "US CERT"
		reference = "https://www.us-cert.gov/ncas/alerts/TA14-353A"

	strings:

		$strl  = "{ C6 45 E8 64 C6 45 E9 61 C6 45 EA 79 C6 45 EB 69 C6 45 EC 70 C6 45 ED 6D C6 45 EE 72 C6 45 EF 2E C6 45 F0 74 C6 45 F1  62 C6 45 F2 6C }" // 'dayipmr.tbl' being moved to ebp

	condition:
		(uint16(0) == 0x5A4D or uint16(0) == 0xCFD0 or uint16(0) == 0xC3D4 or uint32(0) == 0x46445025 or uint32(1) == 0x6674725C) and all of them
}

rule Lightweight_Backdoor_4

{

	meta:
		author = "US CERT"
		reference = "https://www.us-cert.gov/ncas/alerts/TA14-353A"

	strings:

		$strl  = { C6 45 F4 61 C6 45 F5 6E C6 45 F6 73 C6 45 F7 69 C6 45 F8 2E C6 45 F9 6E C6 45 FA 6C C6 45 FB 73 } // 'ansi.nls' being moved to ebp

	condition:
		(uint16(0) == 0x5A4D or uint16(0) == 0xCFD0 or uint16(0) == 0xC3D4 or uint32(0) == 0x46445025 or uint32(1) == 0x6674725C) and all of them

}

rule Lightweight_Backdoor_5

{

	meta:
		author = "US CERT"
		reference = "https://www.us-cert.gov/ncas/alerts/TA14-353A"

	strings:
		$strl  = { C6 45 F4 74 C6 45 F5 6C C6 45 F6 76 C6 45 F7 63 C6 45 F8 2E C6 45 F9 6E C6 45 FA 6C C6 45 FB 73 } // 'tlvc.nls' being moved to ebp

	condition:
		(uint16(0) == 0x5A4D or uint16(0) == 0xCFD0 or uint16(0) == 0xC3D4 or uint32(0) == 0x46445025 or uint32(1) == 0x6674725C) and all of them

}

rule Lightweight_Backdoor_6

{
	meta:
		author = "US CERT"
		reference = "https://www.us-cert.gov/ncas/alerts/TA14-353A"

	strings:
		$STR1 = "{ 8A 10 80 ?? 4E 80 ?? 79 88 10}"
		$STR2 = "{ SA 10 80 ?? 79 80 ?? 4E 88 10}"

	condition:
		(uint16(0) == 0x5A4D or uint16(0) == 0xCFD0 or uint16(0) == 0xC3D4 or uint32(0) == 0x46445025 or uint32(1) == 0x6674725C) and all of them

}

rule Malware_used_by_cyber_threat_actor_1

{
	meta:
		author = "US CERT"
		reference = "https://www.us-cert.gov/ncas/alerts/TA14-353A"

	strings:
		$heapCreateFunction_0 = {33C06A003944240868001000000F94C050FF15????????85C0A3???????07436E893FEFFFF83F803A3???????0750D68F8030000E8??00000059EB0A83F8027518E8????000085C0750FFF35???????0FF15???????033C0C36A0158C3}
		$heapCreateFunction = "{558BECB82C120000E8????FFFF8D8568FFFFFF5350C78568FFFFFF94000000FF1????????085C0741A83BD78FFFFFF02751183BD6CFFFFFF0572086A0158E9020100008D85D4EDFFF68901000005068???????0FF15???????085C00F84D000000033DB8D8DD4EDFFFF389DD4EDFFFF74138A013C617C083C7A7F042C20880141381975ED8D85D4EDFFFF6A165068???????0E8????000083C40C85C075088D85D4EDFFFFEB498D8564FEFFFF68040100005053FF15???????0389D64FEFFFF8D8D64FEFFFF74138A013C617C083C7A7F042C20880141381975ED8D8564FEFFFF508D85D4EDFFFF50E8????????59593BC3743E6A2C50E8????????593BC3597430408BC83818740E80393B75048819EB0141381975F26A0A5350E8????000083C40C83F802741D83F803741883F80174138D45FC50E898FEFFFF807DFC06591BC083C0035BC9C3}"
		$getMajorMinorLinker = {568B7424086A00832600FF15???????06681384D5A75148B483C85C9740D03C18A481A880E8A401B8846015EC3}
		$openServiceManager = {FF15???0?0?08B?885??74????????????????5?FF15???0?0?08B?????0?0?08BF?85F?74}
	
	condition:
		all of them
}


rule Malware_used_by_cyber_threat_actor_2 

{
	meta:
		author = "US CERT"
		reference = "https://www.us-cert.gov/ncas/alerts/TA14-353A"

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
 
 rule Malware_used_by_cyber_threat_actor_3 

{
	meta:
		author = "US CERT"
		reference = "https://www.us-cert.gov/ncas/alerts/TA14-353A"

	strings:
		$STR1 = { 50 68 80 00 00 00 68 FF FF 00 00 51 C7 44 24 1C 3a 8b 00 00 }

	condition:
		(uint16(0) == 0x5A4D or uint16(0) == 0xCFD0 or uint16(0) == 0xC3D4 or uint32(0) == 0x46445025 or uint32(1) == 0x6674725C) and all of them
}


rule Proxy_Tool

{
	meta:
		author = "US CERT"
		reference = "https://www.us-cert.gov/ncas/alerts/TA14-353A"

	strings:
		$STR1 = "pmsconfig.msi" wide
		$STR2 = "pmslog.msi" wide

	condition:
		(uint16(0) == 0x5A4D or uint16(0) == 0xCFD0 or uint16(0) == 0xC3D4 or uint32(0) == 0x46445025 or uint32(1) == 0x6674725C) and any of them
}

rule Proxy_Tool_2

{
	meta:
		author = "US CERT"
		reference = "https://www.us-cert.gov/ncas/alerts/TA14-353A"

	strings:
    	$STR1 = "{ 82 F4 DE D4 D3 C2 CA F5 C8 C8 D3 82 FB F4 DE D4 D3 C2 CA 94 95 FB D4 Dl  C4 CF C8 D4 D3 89 C2 DF C2 87 8A CC 87 00 }" // '%SystemRoot%\System32\svchost.exe -k' xor A7

	condition:
		(uint16(0) == 0x5A4D or uint16(0) == 0xCFD0 or uint16(0) == 0xC3D4 or uint32(0) == 0x46445025 or uint32(1) == 0x6674725C) and all of them

}


rule Proxy_Tool_3
{
	meta:
		author = "US CERT"
		reference = "https://www.us-cert.gov/ncas/alerts/TA14-353A"

	strings:
		$STR2 = {8A 04 17 8B FB 34 A7 46 88 02 83 C9 FF}

	condition:
		(uint16(0) == 0x5A4D or uint16(0) == 0xCFD0 or uint16(0) == 0xC3D4 or uint32(0) == 0x46445025 or uint32(1) == 0x6674725C) and $STR2
}

rule SMB_Worm_Tool

{

	meta:
		author = "US CERT"
		reference = "https://www.us-cert.gov/ncas/alerts/TA14-353A"

    strings:

		$STR1 = "Global\\FwtSqmSession106829323_S-1-5-19"
		$STR2 ="EVERYONE"
		$STR3 = "y0uar3@s!llyid!07,ou74n60u7f001"
		$STR4 = "\\KB25468.dat" 

	condition:
		(uint16(0) == 0x5A4D or uint16(0) == 0xCFD0 or uint16(0) ==0xC3D4 or uint32(0) == 0x46445025 or uint32(1) == 0x6674725C) and all of them
}