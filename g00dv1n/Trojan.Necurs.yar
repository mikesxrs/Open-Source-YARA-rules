rule TrojanWin32NecursSample
{
 	meta:
 		Description  = "Trojan.Necurs.sm"
 		ThreatLevel  = "5"

 	strings:
		$ = "some stupid error %u" ascii wide
		$ = "loading" ascii wide
		$ = "unloading" ascii wide
		$ = "exception %08x %swhen %s at %p" ascii wide
		$ = "microsoft.com" ascii wide
		$ = "facebook.com" ascii wide
		$a = "NitrGB" ascii wide
		$ = "\\Installer\\{" ascii wide
		$ = "%s%0.8X-%0.4X-%0.4X-%0.4X-%0.8X%0.4X}\\" ascii wide
		$ = "syshost32" ascii wide
		$ = "%s\\svchost.exe" ascii wide

 	condition:
 		(8 of them) or $a
}

rule TrojanWinNTNecursSample
{
 	meta:
 		Description  = "Trojan.Necurs.sm"
 		ThreatLevel  = "5"

 	strings:
		$a = "F:\\cut\\abler\\detecting\\overlapping\\am.pdb" ascii wide
		$ = "VirusBuster Ltd" ascii wide
		$ = "Beijing Jiangmin" ascii wide
		$ = "SUNBELT SOFTWARE" ascii wide
		$ = "Sunbelt Software" ascii wide
		$ = "K7 Computing" ascii wide
		$ = "Immunet Corporation" ascii wide
		$ = "Beijing Rising" ascii wide
		$ = "G DATA Software" ascii wide
		$ = "Quick Heal Technologies" ascii wide
		$ = "Comodo Security Solutions" ascii wide
		$ = "CJSC Returnil Software" ascii wide
		$ = "NovaShield Inc" ascii wide
		$ = "BullGuard Ltd" ascii wide
		$ = "Check Point Software Technologies Ltd" ascii wide
		$ = "Panda Software International" ascii wide
		$ = "Kaspersky Lab" ascii wide
		$ = "FRISK Software International Ltd" ascii wide
		$ = "ESET, spol. s r.o." ascii wide
		$ = "Doctor Web Ltd" ascii wide
		$ = "BitDefender SRL" ascii wide
		$ = "BITDEFENDER LLC" ascii wide
		$ = "Avira GmbH" ascii wide
		$ = "GRISOFT, s.r.o." ascii wide
		$ = "PC Tools" ascii wide
		$ = "ALWIL Software" ascii wide
		$ = "Agnitum Ltd" ascii wide

 	condition:
 		(8 of them) or $a
}