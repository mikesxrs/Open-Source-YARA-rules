rule TrojanDropperWin32Gamarue_A_Andromeda
{
 	meta:
 		Description  = "Trojan.Andromeda.sm"
 		ThreatLevel  = "5"

 	strings:
		$ = { 66 8B 10 66 3B 11 75 1E 66 3B D3 74 15 66 8B 50 02 66 3B 51 02 75 0F 83 C0 04 83 C1 04 66 3B D3 75 DE 33 C0 EB 05 1B C0 83 D8 FF 3B C3 0F 84 ?? ?? ?? ?? 8D 85 ?? ?? ?? ?? ?? 56 FF D7 85 C0 75 ?? }
		$a = "ldr\\CUSTOM\\local\\local\\Release\\ADropper.pdb" ascii wide
		$ = "EpisodeNorth.exe" ascii wide
		$ = "HandballChampionship.exe" ascii wide
		$ = "\\#MSI" ascii wide
		$ = "\\MSI" ascii wide
		$ = "\\msiexec.exe" ascii wide
		$ = "avp.exe" ascii wide
		$ = "\\(empty).lnk" ascii wide
		$b = "hsk\\ehs\\dihviceh\\serhlsethntrohntcohurrehem\\chsyst" ascii wide

 	condition:
 		(3 of them) or $a or $b
}
