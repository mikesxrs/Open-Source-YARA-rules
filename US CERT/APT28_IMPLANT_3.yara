rule IMPLANT_3_v1
{
meta:
	author = "US-CERT"
	description = "X-Agent/CHOPSTICK"
	reference = "https://www.us-cert.gov/sites/default/files/publications/AR-17-20045_Enhanced_Analysis_of_GRIZZLY_STEPPE_Activity.pdf"

strings:
	$STR1 = ">process isn't exist<" ascii wide
	$STR2 = "shell\\open\\command=\"System Volume Information\\USBGuard.exe\" install" ascii wide
	$STR3 = "User-Agent: Mozilla/5.0 (Windows NT 6.; WOW64; rv:20.0) Gecko/20100101 Firefox/20.0" ascii wide
	$STR4 = "webhp?rel=psy&hl=7&ai=" ascii wide
	$STR5 = {0f b6 14 31 88 55 ?? 33 d2 8b c1 f7 75 ?? 8b 45 ?? 41 0f b6 14 02 8a 45 ?? 03 fa}

condition:
	any of them
}


rule IMPLANT_3_v2
{
meta:
	author = "US-CERT"
	description = "X-Agent/CHOPSTICK"
	reference = "https://www.us-cert.gov/sites/default/files/publications/AR-17-20045_Enhanced_Analysis_of_GRIZZLY_STEPPE_Activity.pdf"
strings:
	$base_key_moved = {C7 45 ?? 3B C6 73 0F C7 45 ?? 8B 07 85 C0 C7 45 ?? 74 02 FF D0 C7 45 ??
83 C7 04 3B C7 45 ?? FE 72 F1 5F C7 45 ?? 5E C3 8B FF C7 45 ?? 56 B8 D8 78 C7 45 ?? 75 07 50 E8
C7 45 ?? B1 D1 FF FF C7 45 ?? 59 5D C3 8B C7 45 ?? FF 55 8B EC C7 45 ?? 83 EC 10 A1 66 C7 45 ??
33 35}
	$base_key_b_array = {3B C6 73 0F 8B 07 85 C0 74 02 FF D0 83 C7 04 3B FE 72 F1 5F 5E C3 8B
FF 56 B8 D8 78 75 07 50 E8 B1 D1 FF FF 59 5D C3 8B FF 55 8B EC 83 EC 10 A1 33 35 }
condition:
	(uint16(0) == 0x5A4D or uint16(0) == 0xCFD0 or uint16(0) == 0xC3D4 or uint32(0) == 0x46445025 or uint32(1) == 0x6674725C) and any of them
}

rule IMPLANT_3_v3
{
meta:
	author = "US-CERT"
	description = "X-Agent/CHOPSTICK"
	reference = "https://www.us-cert.gov/sites/default/files/publications/AR-17-20045_Enhanced_Analysis_of_GRIZZLY_STEPPE_Activity.pdf"
strings:
	$STR1 = ".?AVAgentKernel@@"
 	$STR2 = ".?AVIAgentModule@@"
 	$STR3 = "AgentKernel"
condition:
	(uint16(0) == 0x5A4D or uint16(0) == 0xCFD0 or uint16(0) == 0xC3D4 or uint32(0) == 0x46445025 or uint32(1) == 0x6674725C) and any of them
}
