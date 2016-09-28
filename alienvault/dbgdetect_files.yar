rule dbgdetect_files : dbgdetect
{
	meta:
		author = "AlienVault Labs"
		type = "info"
		severity = 1
		description = "Debugger detection tricks"
	strings:
		$file1 = "syserdbgmsg" nocase ascii wide
		$file2 = "syserboot" nocase ascii wide
		$file3 = "SICE" nocase ascii wide
		$file4 = "NTICE" nocase ascii wide
	condition:
		2 of them
}