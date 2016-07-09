rule sakula_dropper_v3_1
{
    meta:
        description = "Sakula v3.1 dropper"
        date = "2015-10-13"
        author = "Airbus Defence and Space Cybersecurity CSIRT - Yoann Francou"
        reference = "http://blog.airbuscybersecurity.com/post/2015/10/Malware-Sakula-Evolutions-%28Part-2/2%29"
    strings:
        $m1 = "/c ping 127.0.0.1 & del /q \"%s\""
        $m2 = "%TEMP%\\"
        $m3 = "s.exe"
        $m4 = "setup.msi"
        $m5 = "msi.dll"
    condition:
        all of them
}