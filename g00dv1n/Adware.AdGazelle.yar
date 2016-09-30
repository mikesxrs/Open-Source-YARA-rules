rule AdwareAdGazelleSample
{
	meta:
		Description  = "Adware.AdGazelle.vb"
		ThreatLevel  = "5"

	strings:

		$ = "D:\\popajar3" ascii wide
		$ = "squeakychocolate" ascii wide
		$ = "squeaky chocolate" ascii wide
		$ = "adxloader.dll" ascii wide
		$ = "adxloader.pdb" ascii wide
		$ = "adxloader64.dll" ascii wide
		$ = "adxloader64.pdb" ascii wide
		$ = "d:\\Products\\ADX.IE.8" ascii wide

	condition:
		any of them
}