rule TrojanDropperMicrojoin
{
	meta:
		Description  = "Trojan.Microjoin.rc"
		ThreatLevel  = "5"

	strings:
		$ep = { 55 8B EC 6A FF 68 00 00 00 00 68 00 00 00 00 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 83 EC 68 53 56 57 5F 5E 5B 33 C0 83 C4 78 5D }

	condition:
		$ep at entrypoint
}