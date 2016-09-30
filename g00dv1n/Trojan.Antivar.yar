rule TrojanWin32AntivarSample
{
	meta:
		Description  = "Trojan.Antivar.sm"
		ThreatLevel  = "5"
	strings:
		$ = "ServerNabs4" ascii wide
		$ = "\\system32\\antivar.exe" ascii wide
	condition:
		any of them
}