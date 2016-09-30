rule TrojanWin32CitadelSampleA
{
	meta:
		Description  = "Trojan.Citadel.sm"
		ThreatLevel  = "5"

	strings:
		$a = "Coded by BRIAN KREBS for personal use only. I love my job & wife." ascii wide
		$hex_string = {85 C0 7? ?? 8A 4C 30 FF 30 0C 30 48 7?}
		$ = "softpc.new" ascii wide
		$ = "CS:%04x IP:%04x OP:%02x %02x %02x %02x %02x" ascii wide

	condition:
		any of them
}