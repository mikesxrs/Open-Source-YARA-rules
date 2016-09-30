rule BetterSurfASample
{
    meta:
        Description = "Adware.BetterSurf.A.vb"
        ThreatLevel = "5"

    strings:
        $n1 = "Media Buzz" ascii wide
        $n2 = "MediaBuzz" ascii wide

        //$script1 = "document.getElementById('wsu_js" ascii wide
        //$script2 = "script.setAttribute('id','wsu_js" ascii wide

    condition:
       all of ($n*)
}