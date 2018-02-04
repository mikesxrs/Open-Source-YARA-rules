rule doc_zws_flash {
    meta:
    ref ="2192f9b0209b7e7aa6d32a075e53126d"
    author = "MalwareTracker.com"
    date = "2013-01-11"
    blog = "http://blog.malwaretracker.com/2014/01/cve-2013-5331-evaded-av-by-using.html"

    strings:
        $header = {66 55 66 55 ?? ?? ?? 00 5A 57 53}
        $control = "CONTROL ShockwaveFlash.ShockwaveFlash"
       
    condition:
        all of them 
}
