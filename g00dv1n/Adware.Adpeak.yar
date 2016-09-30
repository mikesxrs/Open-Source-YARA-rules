rule AdwareAdpeakSample
{
	meta:
		Description  = "Adware.Adpeak.vb"
		ThreatLevel  = "5"

	strings:

		$ = "dealcabby.dll" ascii wide
		$ = "getsavin.dll" ascii wide

	condition:
		any of them
}