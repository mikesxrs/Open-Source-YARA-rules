rule TrojanDownloaderWin32Frethog_E_Sample
{
 	meta:
 		Description  = "Trojan.Frethog.sm"
 		ThreatLevel  = "5"

 	strings:
 		$ = "C:\\WINDOWS\\system32\\msvbvm60.dll\\3" ascii wide
		$ = "DownLoad File:" ascii wide
		$ = "\\system32\\mswinsck.ocx" ascii wide

		$ = "http://www.pc918.net/file.txt" ascii wide
		$ = "http://www.yswm.net/file.txt" ascii wide
		$ = "http://www.v138.net/file.txt" ascii wide
		$ = "http://www.v345.net/file.txt" ascii wide
		$ = "http://www.ahwm.net/file.txt" ascii wide
		$ = "http://user.yswm.net/yswm" ascii wide

		$ = "so118config" ascii wide
		$ = "http://user.yswm.net" ascii wide
		$ = "hide.exe" ascii wide
		$ = "\\win.ini" ascii wide
		$ = "\\system32\\svchost.exe" ascii wide
		$ = "P2P DownFile:" ascii wide
		$ = "yswm.runsoft" ascii wide
		$ = "\\sys.dat" ascii wide

 	condition:
 		4 of them
}