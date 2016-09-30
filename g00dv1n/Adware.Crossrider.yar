rule AdwareCrossriderSampleA
{
	meta:
		Description  = "Adware.Crossrider.A.sm"
		ThreatLevel  = "5"

	strings:
		$ = "-bho.dll" ascii wide
		$ = "-bho64.dll" ascii wide
		$ = "-buttonutil64.dll" ascii wide
		$ = "-buttonutil.dll" ascii wide
		$ = "-BrowserEventSandBox" ascii wide
		$ = "CrossriderApp" ascii wide
		$ = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\App Paths\\chrome.exe" ascii wide
		$ = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\App Paths\\firefox.exe" ascii wide
		$ = "IEInject_Win32.dll" ascii wide
		$ = "bg_debug.js" ascii wide
		$ = "new_debug.js" ascii wide
		$ = "Browser Process id" ascii wide
		$ = "BHO Process id" ascii wide
		$ = "BhoRunningVersion" ascii wide
		$ = "-nova64.dll" ascii wide

		$str1 = "crossrider-buttonutil.pdb" ascii wide
		$str2 = "AVCCrossriderButtonHelper" ascii wide
		$str3 = "AVCCrossRiderLogger" ascii wide
		$str5 = "AddCrossRiderSearchProvider" ascii wide
		$str6 = "C:\\BUILD_AVZR2\\WhiteRabbit" ascii wide
		$str7 = "CrossriderBHO" ascii wide
		$str8 = "215AppVerifier" ascii wide
		$str9 = "Crossrider BHO Version" ascii wide
		$str10 = "brightcircleinvestments.com" ascii wide
		$str11 = "CrossriderNotification.pdb" ascii wide
		$str12 = "C:\\Users\\cross\\Desktop\\compilation_bot_area" ascii wide
	condition:
		(3 of them) or (any of ($str*))
}

rule AdwareCrossriderSampleB
{
	meta:
		Description  = "Adware.Crossrider.B.vb"
		ThreatLevel  = "5"

	strings:
		$ = "crossbrowse/updater/{{camp_id}}/{{version}}/{{secret}}/update.json" ascii wide
		$ = "Crossbrowse\\Crossbrowse\\Application\\crossbrowse.exe" ascii wide
		$ = "allnetserveline.com/crossbrowse" ascii wide
		$ = "C:\\workspace\\crossbrowse" ascii wide
		$ = "CrossriderBrowserInstaller.pdb" ascii wide

	condition:
		any of them
}
