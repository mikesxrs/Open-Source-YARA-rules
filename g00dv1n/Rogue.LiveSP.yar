rule RogueWin32LiveSecurityProfessional
{
	meta:
		Description  = "Rogue.LiveSP.sm"
		ThreatLevel  = "5"
	strings:
		$ = "W32.SillyFDC.BDQ" ascii wide
		$ = "Trojan.Peancomm" ascii wide
		$ = "Adware.Borlan" ascii wide
		$ = "Trojan.Exprez" ascii wide
		$ = "Sunshine.B" ascii wide
		$ = "SecurityRisk.URLRedir" ascii wide
		$ = "Spyware.Ezurl" ascii wide
		$ = "W32.Azero.A" ascii wide
		$ = "W32.Downloadup.B" ascii wide
		$ = "Hacktool.Unreal.A" ascii wide
		$ = "Backdoor.Rustock.B" ascii wide
		$ = "Infostealer.Snifula.B" ascii wide
		$ = "Adware.FCHelp" ascii wide
		$ = "Adware.Invinciblekey" ascii wide
		$ = "Packed.Dromedan!gen5" ascii wide
		$ = "Downloader.Jadelile" ascii wide
		$ = "SecShieldFraud!gen7" ascii wide
		$ = "Trojan.Komodola" ascii wide
		$ = "W32.Stekct" ascii wide
		$ = "Packed.Generic.368" ascii wide
		$ = "VirusDoctor!gen12" ascii wide
		$ = "UnlockAV" ascii wide
		$ = "Sign Up in Live Security Professional" ascii wide
		$ = "General security:" ascii wide
		$ = "Real-Time Shields:" ascii wide
		$ = "Self-protection from malware:" ascii wide
		$ = "Definitions auto updates:" ascii wide
		$ = "Virus definition version:" ascii wide
		$ = "Program version:" ascii wide
		$ = "Live Security Professional %s." ascii wide
		$ = "You have a license" ascii wide
		$ = "Your system is protected from possible threats." ascii wide
		$ = "3.13.44.20" ascii wide
		$ = "Protection level:" ascii wide
		$ = "Your computer is fully protected." ascii wide
		$ = "Your protection against viruses and spyware is weak" ascii wide
		$ = "You must enter the serial number that came to your email to activate your license." ascii wide
		$ = "Live Security Professional - Unregistered version" ascii wide
		$ = "Scan stopped..." ascii wide
		$ = "Scan paused..." ascii wide
		$ = "http://185.6.80.65/index.php?r=checkout" ascii wide
		$ = "To complete the registration, check your data for correctness." ascii wide
		$ = "You have successfully signed up and choose a license. After confirming the payment (about 10 minutes), you get a completely secure system." ascii wide
		$ = "Live Security Professional has blocked" ascii wide
		$ = "Live security professional" ascii wide
		$ = "Successfully Cleared!" ascii wide
		$ = "DETECTED VIRUSES" ascii wide
		$ = "List of detected viruses." ascii wide
		$ = "Total infected:" ascii wide
		$ = "10% of the viruses were treated free. For the cure of all viruses, you must purchase a license Pro or Pro Plus." ascii wide
	condition:
		5 of them
}