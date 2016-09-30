rule AdwareDownloaderA
{
	meta:
		Description  = "Adware.Downloader.A.vb"
		ThreatLevel  = "5"

	strings:

		$ = "odiassi" ascii wide
		$ = "stavers" ascii wide
		$ = "trollimog" ascii wide
		$ = "diapause" ascii wide
		$ = "UserControl1" ascii wide
		$ = "listboxmod01" ascii wide

	condition:
		all of them
}