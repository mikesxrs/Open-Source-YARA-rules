rule AdwareInstallCoreSample
{
	meta:
		Description  = "Adware.InstallCore.vb"
		ThreatLevel  = "5"

	strings:

		$ = "www.mynicepicks.com" ascii wide
		$ = "www.ultimatepdfconverter.com" ascii wide
		$ = "www.coolpdfcreator.com" ascii wide
		$ = "cdnus.ironcdn.com" ascii wide
		$ = "esd.baixaki.com.br" ascii wide
		$ = "cdneu2.programmersupply.com" ascii wide

	condition:
		any of them
}