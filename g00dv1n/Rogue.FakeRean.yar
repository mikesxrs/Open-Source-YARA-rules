rule RogueFakeDefenderSample
{
	meta:
		Description  = "Rogue.FakeDef.sm"
		ThreatLevel  = "5"

	strings:
		$a = "pcdfdata" 		ascii wide
		$b = "toplevel_pcdef" 	ascii wide
		
		$ = "%spld%d.exe" ascii wide
		$ = "avsrun.exe" ascii wide
		$ = "avsdel.exe" ascii wide
		
		$ = "vl.bin" ascii wide
		$ = "reginfo.bin" ascii wide
		
		$ = "%s%s.lnk" ascii wide
		$ = "%sRemove %s.lnk" ascii wide
		$ = "Uninstaller application" ascii wide
		$ = "%s%s Help and Support.lnk" ascii wide
		
		$ = "pavsdata" ascii wide
		$ = "avsmainwnd" ascii wide
		$ = "avsdsvc" ascii wide
		$ = "ovcf" ascii wide
		
		$ = "Global\\avsinst" ascii wide
		$ = "Global\\avscfglock" ascii wide
		$ = "\\loc\\reg\\conn\\activate" ascii wide
		$ = "\\forms\\alerts\\vulner" ascii wide
		$ = "\\forms\\alerts\\hack" ascii wide
		
		$ = "Software\\Classes\\.exe" ascii wide
		
		$ = "%s was infected with %s and has been successfully repaired" ascii wide
		$ = "Attack %s from remote host %d.%d.%d.%d has been successfully blocked" ascii wide
			
		$ = "http://%s/api/ping?stage=1&uid=%S&id=%d&subid=%d&os=%d&avf=%d" ascii wide
		$ = "http://%s/api/ping?stage=2&uid=%S&success=%d" ascii wide
		$ = "http://%s/api/ping?stage=3&uid=%S" ascii wide
		$ = "http://%s/content/scc" ascii wide
		$ = "http://%s/postload2/?uid=%S" ascii wide
		$ = "http://%S/api/test" ascii wide
		$ = "http://%s/load/?uid=%S" ascii wide
		$ = "http://%s/html/viruslist/?uid=%S" ascii wide
		$ = "https://%s/billing/key/?uid=%S" ascii wide
		$ = "https://%s/html/billing/?uid=%S" ascii wide

	condition:
		3 of them
}

rule RogueFakeReanInternetSecuritySample
{
	meta:
		Description  = "Rogue.FakeRean.sm"
		ThreatLevel  = "5"

	strings:
		$ = "VB82ea936a-6aa61dbf" ascii wide
		$ = "VBOX HARDDISK" ascii wide
		$ = "avbase.dat" ascii wide
		$ = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" ascii wide
		$ = "ORDER #:" ascii wide
		$ = "Thank you, the program is now registered!" ascii wide
		$ = "To continue please restart the program. Press OK to close the program." ascii wide
		$ = "Wrong activation code! Please check and retry" ascii wide
		$ = "license. As soon as you complete the activation you will" ascii wide
		$ = "This option is available only in the activated version of " ascii wide
		$ = "You must activate the program by entering registration information " ascii wide
		$ = "has detected that a new Threat Database is available." ascii wide
		$ = "items are critical privacy compromising content"
		$ = "items is medium privacy threats" ascii wide
		$ = "items are junk content of low privacy threats" ascii wide
		$ = "has detected a leak of your files though the Internet. " ascii wide
		$ = "We strongly recommend that you block the attack immediately" ascii wide
		$ = "All threats has been succesfully removed." ascii wide
		$ = "Attention! We strongly recommend that you activate " ascii wide
		$ = "for the safety and faster running of your PC." ascii wide
		$ = "No new update available" ascii wide
		$ = "Could not connect to server!" ascii wide
		$ = "New updates are installed successfully!" ascii wide
		$ = "Security Warning!" ascii wide
		$ = "Malicious program has been detected." ascii wide
		$ = "Click here to protect your computer." ascii wide
		$ = "is infected by W32/Blaster.worm" ascii wide
		$ = "$$$$$$$$.bat" ascii wide
		$ = "Completed!" ascii wide
		$ = "Antivirus software uninstalled successfully" ascii wide
		$ = "Antivirus uninstall is not success. Please try again..." ascii wide
		$ = "-uninstall" ascii wide
		$ = "_MUTEX" ascii wide
		$ = "/min" ascii wide
		
	condition:
		7 of them
}

rule RogueUnknownFakeAV
{
	meta:
		Description  = "Rogue.FakeRean.rc"
		ThreatLevel  = "5"
		
	strings:
		$a = "S:\\appointed\\commanding\\general\\Moravia\\Image[01].exe" ascii wide
		$b = "Dresden blockade" ascii wide
		$c = "37592837532" ascii wide
		$d = "39874598234" ascii wide
		$e = "465234750238947532649587203948523-4572304750329458-23459723450-23457" ascii wide
		
	condition:
		($a and $b) or ($c and $d) or $e
}

rule RoguePCDefender
{
	meta:
		Description  = "Rogue.FakeDef.rc"
		ThreatLevel  = "5"
		
	strings:
		$hex0 = { 8A 4A 01 56 57 33 FF 47 8B C7 8D 72 03 85 C0 74 28 80 C1 0B 80 F9 5A 7E 11 0F BE C1 83 E8 41 6A 19 99 59 F7 F9 80 C2 41 8A CA 33 C0 38 0E 0F 94 C0 47 46 46 83 FF 10 7C D4 5F 5E C3 }
		
	condition:
		any of ($hex*)
}