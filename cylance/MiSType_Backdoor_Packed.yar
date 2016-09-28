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