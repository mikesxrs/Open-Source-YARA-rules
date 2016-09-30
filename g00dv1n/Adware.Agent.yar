rule AdwarePricePeepSample
{
	meta:
		Description  = "Adware.PricePeep.vb"
		ThreatLevel  = "5"

	strings:

		$ = "BrandedUpdater" ascii wide
		$ = "default_browser" ascii wide
		$ = "LaunchDefaultBrowser" ascii wide
		$ = "LaunchBrowser" ascii wide

		$a1 = "InstallUtil.pdb" ascii wide
		$a2 = "C:\\managed\\root\\VTG_" ascii wide
		$a3 = "InstallUtil.pdb" ascii wide
		$a4 = "BrandedUpdater.pdb" ascii wide
		//$a5 = "PricePeep" ascii wide
		$a6 = "InstallUtil.cpp" ascii wide
		$a7 = "BrandedUpdater.cpp" ascii wide

	condition:
		(3 of them) or (any of ($a*))
}