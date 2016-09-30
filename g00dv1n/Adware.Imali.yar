rule AdwareImaliSample
{
	meta:
		Description  = "Adware.Imali.vb"
		ThreatLevel  = "5"

	strings:

		$ = "www.freemediaplayer.tv" ascii wide

	condition:
		any of them
}