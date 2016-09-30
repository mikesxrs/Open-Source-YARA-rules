rule AdwareDealPlySample
{
	meta:
		Description  = "Adware.DealPly.vb"
		ThreatLevel  = "5"

	strings:

		$ = "dealply.prq" ascii wide

	condition:
		any of them
}