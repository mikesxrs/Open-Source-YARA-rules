rule AdwareiBryteSample
{
	meta:
		Description  = "Adware.iBryte.vb"
		ThreatLevel  = "5"

	strings:

		$ = "install.ibryte.com" ascii wide
		$ = "pn-installer28.com" ascii wide

	condition:
		any of them
}