rule AdwareConvertAdSample
{
	meta:
		Description  = "Adware.ConvertAd.vb"
		ThreatLevel  = "5"

	strings:

		$ = "http://download-servers.com/SysInfo/adrouteservice/adrouter.php" ascii wide
		$ = "ConvertAd.html" ascii wide
		$ = "ConvertAd.exe" ascii wide

	condition:
		any of them
}