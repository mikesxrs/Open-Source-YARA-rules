rule CorkowDLL
{
meta:
	description = "Rule to detect the Corkow DLL files"
    reference = "www.group-ib.ru/brochures/Group-IB-Corkow-Report-EN.pdf"
strings:
	$mz = { 4d 5a }
	$binary1 = {60 [0-8] 9C [0-8] BB ?? ?? ?? ?? [0-8] 81 EB ?? ?? ?? ?? [0-8] E8 ?? 00 00 00 [0-8] 58 [0-8] 2B C3}
	$binary2 = {(FF 75 ?? | 53) FF 75 10 FF 75 0C FF 75 08 E8 ?? ?? ?? ?? [3-9] C9 C2 0C 00}
	$export1 = "Control_RunDLL"
	$export2 = "ServiceMain"
	$export3 = "DllGetClassObject"
condition:
	($mz at 0) and ($binary1 and $binary2) and any of ($export*)
}