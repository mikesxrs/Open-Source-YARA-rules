rule AdwareBrowseFoxSample
{
	meta:
		Description  = "Adware.BrowseFox.vb"
		ThreatLevel  = "5"

	strings:

		$a2 = ".expextdll.dll" ascii wide
		$a3 = ".IEUpdate.pdb" ascii wide
		$a4 = ".Repmon.dll" ascii wide
		$a5 = ".BRT.Helper.exe" ascii wide
		$a6 = ".BrowserAdapter.pdb" ascii wide
		$a7 = ".expextdll.dll" ascii wide
		$a8 = ".browseradapter64.exe" ascii wide
		$a9 = ".purbrowse.exe" ascii wide
		$a10 = "BrowserFilter.exe" ascii wide
		$a11 = ".Bromon.dll" ascii wide
		$a12 = ".OfSvc.dll" ascii wide
		$a13 = ".GCUpdate.dll" ascii wide
		$a14 = ".BroStats.dll" ascii wide
		$a15 = ".BOAS.dll" ascii wide
		$a16 = ".BrowserAdapterS.dll" ascii wide
		$a17 = ".PurBrowse64.exe" ascii wide

		$b1 = "system32\\drivers\\%s.sys" ascii wide
		$b2 = "FilterApp" ascii wide

	condition:
		(any of ($a*)) or (all of ($b*))
}