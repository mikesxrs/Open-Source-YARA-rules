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