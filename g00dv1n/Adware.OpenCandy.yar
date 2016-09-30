rule AdwareOpenCandySample
{
	meta:
		Description  = "Adware.OpenCandy.vb"
		ThreatLevel  = "5"

	strings:

		$ = "http://cdn.opencandy.com" ascii wide

	condition:
		any of them
}