rule PUPSystemOptimizerASample
{
	meta:
		Description  = "PUP.SystemOptimizer.vb"
		ThreatLevel  = "5"

	strings:

		$ = "http://bitest.softservers.net" ascii wide
		$ = "http://bi.softservers.net" ascii wide

	condition:
		any of them
}