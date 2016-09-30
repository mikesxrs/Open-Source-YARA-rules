rule RogueWinwebsecSample
{
	meta:
		Description  = "Rogue.Winwebsec.sm"
		ThreatLevel  = "5"

	strings:
		$a = "%s%s\\%s.ico" ascii wide
		$b = "%s%s\\%s.exe" ascii wide
	condition:
		$a or $b
}

rule RogueSShieldSample
{
	meta:
		Description  = "Rogue.SShield.sm"
		ThreatLevel  = "5"

	strings:
		$a = "64C665BE" 	wide
		$b = "BC0172B25DF2" wide
	condition:
		$a or $b
}