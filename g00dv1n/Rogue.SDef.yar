rule RogueSpywareDefenderSample
{
	meta:
		Description  = "Rogue.SDef.sm"
		ThreatLevel  = "5"

	strings:
		$str1 = "/get_two.php?" ascii wide
		$str2 = "spyware-defender.com" ascii wide
		$str3 = "Spyware Defender 2014" ascii wide
		$str4 = "Antivirus MAC 2014" ascii wide
		$str5 = "Antivirus WIN 2014" ascii wide
		$ = "Delete" ascii wide
		$ = "NoRemove" ascii wide
		$ = "ForceRemove" ascii wide
		$ = "RunInvalidSignatures" ascii wide
		$ = "CheckExeSignatures" ascii wide
	condition:
		(5 of them) or (any of ($str*))
}