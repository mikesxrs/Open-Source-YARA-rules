rule RogueFakeSysDefSample
{
	meta:
		Description  = "Rogue.FakeSysDef.sm"
		ThreatLevel  = "5"

	strings:
		$ = "smtmp" ascii wide
		$ = "attrib -h"  ascii wide
		$ = "%s\\license.dat"  ascii wide
		$ = "Thank you for purchasing %s"    ascii wide
		$ = "%s\\%s_License.txt" ascii wide
		$ = "Bad sectors" ascii wide
		$ = "Lost cluster chains" ascii wide
		$ = "Relocate bad sectors: " ascii wide
		$ = "Fix corrupted files: " ascii wide
		$ = "Fix cluster chain: " ascii wide
		$ = "No errors found. Disk%s health summary %d%%." ascii wide
		$ = "Error 0x00000024 - %s_FILE_SYSTEM" ascii wide
		$ = "Verifying disk consistency..." ascii wide
		$ = "Hard drive spin failure detected" ascii wide
		$ = "Checking S.M.A.R.T. attributes" ascii wide
		$a = "S.M.A.R.T reports" ascii wide
		$ = "Checking HDD surface for bad sectors.." ascii wide
		$ = "Scanning sectors 0x%04X-0x%04X..." ascii wide
		$ = "Check cancelled." ascii wide
		$ = "Hard disk error detected" ascii wide
		$ = "Repair volumes" ascii wide
		$ = "Hard disk verification completed. No errors found." ascii wide
		$ = "Exception Processing Message 0x%08X Parameters" ascii wide
		$ = "Windows - Read error" ascii wide
		$ = "File system on local disk %s contains critical errors" ascii wide
		$ = "explorer.exe - Corrupt Disk" ascii wide
		$ = "svchost.exe - Corrupt Disk" ascii wide

	condition:
		(3 of them) or $a
}