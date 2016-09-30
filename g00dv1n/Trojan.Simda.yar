rule TrojanDroppedBackdoorWin32SimdaSample
{
	meta:
		Description  = "Trojan.Simda.sm"
		ThreatLevel  = "5"

	strings:
		$ = ".driver" ascii wide
		$ = ".userm"  ascii wide
		$ = ".uac64"  ascii wide
		$ = ".mcp"    ascii wide
		$ = ".cfgbin" ascii wide
		$ = ".uacdll" ascii wide
		$ = "%s\\%s.sys" ascii wide
		$ = "%s\\%s.exe" ascii wide
		$ = "%appdata%\\ScanDisc.exe" ascii wide
	condition:
		4 of them
}