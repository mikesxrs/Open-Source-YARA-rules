rule PUPSystweakSample
{
	meta:
		Description  = "PUP.Systweak.vb"
		ThreatLevel  = "5"

	strings:

		$ = "Systweak Software0" ascii wide
		$ = "pc-updater.com/miscservice/miscservice.asmx" ascii wide

	condition:
		any of them
}