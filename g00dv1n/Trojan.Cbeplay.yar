rule TrojanDownloaderCbeplaySample
{
	meta:
		Description  = "Trojan.Cbeplay.sm"
		ThreatLevel  = "5"

	strings:
		$ = "wireshark.exe" ascii wide
		$ = "pstorec.dll" ascii wide
		$ = "ROOT\\SecurityCenter2" ascii wide
		$ = "Select * from AntiVirusProduct" ascii wide
		$ = "SbieDll.dll" ascii wide
		$ = "OPEN %s.mp3 TYPE MpegVideo ALIAS MP3" ascii wide
		$ = "PLAY MP3 wait" ascii wide
		$ = "CLOSE MP3" ascii wide
		$ = "VIRTUALBOX" ascii wide
		$ = "VideoBiosVersion" ascii wide
		$ = "QEMU" ascii wide
		$ = "VMWARE" ascii wide
		$ = "VBOX" ascii wide
		$ = "VIRTUAL" ascii wide
		$ = "taskmgr.exe" ascii wide
		$ = "explorer.exe" ascii wide
		$ = "Program Manager" ascii wide
		$ = "Shell_TrayWnd" ascii wide
		$ = "FriendlyName" ascii wide
		$ = "Capture Filter" ascii wide
		$ = "SampleGrab" ascii wide
		$ = "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer" ascii wide
		$ = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" ascii wide
		$ = "SYSTEM\\CurrentControlSet\\Control\\SafeBoot" ascii wide
		$ = "Hello, visitor from: <strong>" ascii wide
		$ = "SendVoucher" ascii wide
		$ = "winver" ascii wide
		$ = "AVID" ascii wide
		$ = "Emsisoft" ascii wide
		$ = "Lavasoft" ascii wide
		$ = "avast" ascii wide
		$ = "Avira" ascii wide
		$ = "BitDef" ascii wide
		$ = "COMODO" ascii wide
		$ = "F-Secure" ascii wide
		$ = "G Data" ascii wide
		$ = "Kaspersky" ascii wide
		$ = "McAfee" ascii wide
		$ = "ESET" ascii wide
		$ = "Norton" ascii wide
		$ = "Microsoft Security Essentials" ascii wide
		$ = "Panda" ascii wide
		$ = "Sophos" ascii wide
		$ = "Trend Micro" ascii wide
		$ = "Symantec" ascii wide
		$ = "BullGuard" ascii wide
		$ = "VIPRE" ascii wide
		$ = "Webroot" ascii wide
	condition:
		8 of them
}