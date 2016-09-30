rule TrojanRansomRevetonSample
{
	meta:
		Description  = "Trojan.Reveton.sm"
		ThreatLevel  = "5"

	strings:
		$a = "JimmMonsterNew" ascii wide
		$  = "regedit.exe" ascii wide
		$  = "rundll32.exe" ascii wide
		$  = "msconfig.lnk" ascii wide
		$  = "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon" ascii wide
		$  = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\Shell" ascii wide
		$  = "Software\\Microsoft\\Windows\\CurrentVersion\\Run\\ctfmon.exe" ascii wide
	condition:
		(3 of them) or $a
}

rule TrojanWin32UrausySampleA
{
	meta:
		Description  = "Trojan.Urausy.sm"
		ThreatLevel  = "5"

	strings:
		$a = { 55 89 E5 53 56 57 83 0D ?? ?? ?? ?? 01 31 C0 5F 5E 5B C9 C2 04 00 }
		$b = { FF 15 ?? ?? ?? ?? 09 C0 0F 84 ?? ?? ?? ?? 8B 75 ?? 89 C3 6A 01 6A FF 6A 05 56 E8 }

	condition:
		$a and $b
}

rule TrojanRansomWin32TobfySample
{
 	meta:
 		Description  = "Trojan.Tobfy.sm"
 		ThreatLevel  = "5"

 	strings:
		$ = "http://62.109.28.231/gtx3d16bv3/upload/img.jpg" ascii wide
		$ = "http://62.109.28.231/gtx3d16bv3/upload/mp3.mp3" ascii wide

		$ = "Pay MoneyPak" ascii wide
		$ = "You have 72 hours to pay the fine!" ascii wide
		$ = "Wait! Your request is processed within 24 hours." ascii wide
		$a = "G:\\WORK\\WORK_PECEPB\\Work_2012 Private\\Project L-0-ck_ER\\NEW Extern\\inject\\injc\\Release\\injc.pdb" ascii wide
		$b = "G:\\WORK\\WORK_PECEPB\\Work_2012 Private\\Project L-0-ck_ER\\Version V 1.0\\V1.0\\Release\\te.pdb" ascii wide
		$ = "picture.php?pin=" ascii wide
		$ = "s\\sound.mp3" ascii wide
		$ = "s\\1.jpg" ascii wide
		$ = "s\\1.bmp" ascii wide
		$ = "getunlock.php" ascii wide

 	condition:
 		(4 of them) or $a or $b
}