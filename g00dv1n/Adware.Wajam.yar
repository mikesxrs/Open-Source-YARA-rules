rule AdwareWajamSample
{
	meta:
		Description  = "Adware.Wajam.vb"
		ThreatLevel  = "5"

	strings:

		$ = "fastnfreedownload.com" ascii wide
		$ = "InternetEnhancer.exe" ascii wide
		$ = "InternetEnhancerService.exe" ascii wide
		$ = "WJManifest" ascii wide
		$ = "WaInterEnhance" ascii wide
		$ = "ping_wajam" ascii wide
		$ = "D:\\jenkins\\workspace" ascii wide
		$ = "WajamService" ascii wide
		$ = "AVCWJService" ascii wide
		$ = "Internet Enhancer Service" ascii wide

		$a1 = "WajamInternetEnhancerService.pdb" ascii wide
		$a4 = "WHttpServer.pdb" ascii wide
		$a2 = "Wajam. All right reserved" ascii wide
		$a3 = "Wajam.Proxy" ascii wide

	condition:
		(3 of them) or (any of ($a*))
}