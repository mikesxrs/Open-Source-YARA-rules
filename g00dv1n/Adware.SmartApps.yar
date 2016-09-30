rule SmartAppsSample
{
    meta:
        Description = "Adware.SmartApps.vb"
        ThreatLevel = "5"

    strings:

		$a1 = "Unicows.dll" ascii wide
		$a2 = "FrameworkBHO.DLL" ascii wide
		$a3 = "URLDownloadToFile" ascii wide
		$a4 = "getExtensionFileContents" ascii wide
		$a5 = "Toolbar" ascii wide
		$a6 = "GdiplusStartup" ascii wide

        $b1 = "getCookieW" ascii wide
        $b2 = "setCookieW" ascii wide
        $b3 = "InternetSetCookieW" ascii wide
        $b5 = "InternetGetCookieExW" ascii wide

    condition:
        (all of ($b*)) and (any of ($a*))
}