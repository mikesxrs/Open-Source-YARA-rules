rule TrojanBotnetWin32CutwailSample
{
	meta:
		Description  = "Trojan.Cutwail.sm"
		ThreatLevel  = "5"

	strings:
		$ = "PreLoader.pdb" ascii wide
		$ = "magadan21"  ascii wide
		$ = "RkInstall.pdb"  ascii wide
		$ = "InnerDrv.pdb"    ascii wide
		$ = "Protect.pdb" ascii wide
		$ = "MailerApp.pdb" ascii wide
		$ = "revolution6" ascii wide
		$ = "bot25" ascii wide
	condition:
		any of them
}