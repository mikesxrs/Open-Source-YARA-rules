rule sakula_v3_2  {
    meta:
        description = "Sakula v3.2"
        date = "2015-10-13"
        author = "Airbus Defence and Space Cybersecurity CSIRT - Yoann Francou"
        reference = "http://blog.airbuscybersecurity.com/post/2015/10/Malware-Sakula-Evolutions-%28Part-2/2%29"
    strings:
        $m1 = "/c ping 127.0.0.1 & del /q \"%s\""
        $m2 = "%TEMP%\\"
        $m3 = "Emabout.dll"
        $m4 = "Thumbs.db"
        $m5 = "shutil.dll"
        $m6 = "CloseAbout"
                $m7 = "rundll32.exe"

    condition:
        all of them
}