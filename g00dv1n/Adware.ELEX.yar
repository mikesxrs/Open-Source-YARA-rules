rule AdwareELEXSampleA
{
	meta:
		Description  = "Adware.ELEX.A.vb"
		ThreatLevel  = "5"

	strings:

		$ = "www.freeappstools.com" ascii wide
		$ = "dl.elex.soft365.com" ascii wide
		$ = "E:\\Code\\FileSyn\\Bin" ascii wide
		$ = "E:\\Code_SVN\\FileSyn\\Bin" ascii wide

	condition:
		any of them
}


rule AdwareELEXSampleB
{
	meta:
		Description  = "Adware.ELEX.B.vb"
		ThreatLevel  = "5"

	strings:

		$pdb = "Release\\SFKEX.pdb" ascii wide
		$ = "21e223b3f0c97db3c281da1g7zccaefozzjcktmlma" ascii wide
		$ = "http://xa.xingcloud.com/v4/sof-everything" ascii wide
		$ = "http://www.mysearch123.com" ascii wide
		$ = "SFKEX.exe" ascii wide
		$ = "SFKEX.dll" ascii wide
		$ = "SFKURL" ascii wide

	condition:
		2 of them
}


rule AdwareELEXSampleCommon
{
	meta:
		Description  = "Adware.ELEX.vb"
		ThreatLevel  = "5"

	strings:

		$ = "\\Mozilla\\Firefox\\" ascii wide
		$ = "profiles.ini" ascii wide
		$ = "Profile0" ascii wide
		$ = "\\prefs.js" ascii wide
		$ = "\\Google\\Chrome\\User Data\\" ascii wide
		$ = "\\Secure Preferences" ascii wide
		$ = "Software\\Microsoft\\Internet Explorer\\Main" ascii wide
		$ = "Start Page" ascii wide
		$ = "chrome.exe" ascii wide
		$ = "iexplore.exe" ascii wide
		$ = "firefox.exe" ascii wide
		$ = "user_pref" ascii wide
		$ = "browser.startup.homepage" ascii wide
		$ = "startup_urls" ascii wide

	condition:
		all of them
}