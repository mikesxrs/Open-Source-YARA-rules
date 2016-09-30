rule TrojanWin32NedsymGSample
{
	meta:
		Description  = "Trojan.Nedsym.sm"
		ThreatLevel  = "5"

	strings:
		$ = "qwertyuiopasdfghjklzxcvbnm123456789"  ascii wide
		$ = "svcnost.exe"  ascii wide
		$ = "Windows Init"  ascii wide
		$ = "\\drivers\\etc\\hosts"  ascii wide

	condition:
		2 of them
}