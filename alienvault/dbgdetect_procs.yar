rule dbgdetect_procs : dbgdetect
{
	meta:
		author = "AlienVault Labs"
		type = "info"
		severity = 1
		description = "Debugger detection tricks"

	strings:
		$proc1 = "wireshark" nocase ascii wide
		$proc2 = "filemon" nocase ascii wide
		$proc3 = "procexp" nocase ascii wide
		$proc4 = "procmon" nocase ascii wide
		$proc5 = "regmon" nocase ascii wide
		$proc6 = "idag" nocase ascii wide
		$proc7 = "immunitydebugger" nocase ascii wide
		$proc8 = "ollydbg" nocase ascii wide
		$proc9 = "petools" nocase ascii wide

	condition:
		2 of them
}

