rule AdwareGenieoSample
{
    meta:
        Description = "Adware.Genieo.vb"
        ThreatLevel = "5"

    strings:
		$h1 = "gentray.pdb" ascii wide
		$h2 = "genupdater.pdb" ascii wide
		$h3 = "www.genieo.com" ascii wide
        $h4 = "userfeedback-genieo.appspot.com" ascii wide
        $h5 = "Genieo Innovation LTD" ascii wide

        $str1 = "Software\\Genieo" ascii wide
        $str2 = "SOFTWARE\\Genieo" ascii wide

        $str5 = "genieo.exe" ascii wide
        $str6 = "genieutils.exe" ascii wide
        $str7 = "genupdater.exe" ascii wide

        $str8 = "__Genieo_" ascii wide
        $str9 = "GenieoUpdaterServiceCleaner" ascii wide
        $str10 = "GENIEO_TRAY_UI" ascii wide

    condition:
        any of them
}