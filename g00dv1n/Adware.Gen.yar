rule AdwareStormWatchSample
{
	meta:
		Description  = "Adware.StormWatch.vb"
		ThreatLevel  = "5"

	strings:

		$ = "localstormwatch.com" ascii wide
		$ = "StormWatch.pdb" ascii wide
		$ = "StormWatch.exe" ascii wide
		$ = "ActiveDeals" ascii wide

	condition:
		any of them
}