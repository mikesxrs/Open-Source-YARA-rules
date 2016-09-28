rule sakula_v3_1
{
    meta:
        description = "Sakula v3.1"
        date = "2015-10-13"
        author = "Airbus Defence and Space Cybersecurity CSIRT - Yoann Francou"
        reference = "http://blog.airbuscybersecurity.com/post/2015/10/Malware-Sakula-Evolutions-%28Part-2/2%29"
    strings:
        $m1 = "Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1; WOW64; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0)"
        $m2 = ".NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0)"
        $m3 = "Self Process Id:"
        $m4 = "msi.dll"
        $m5 = "setup.msi"
        $m6 = "%WINDIR%\\system32\\svchost.exe"

        $MZ = "MZ"
    condition:
        $MZ at 0 and all of them
}

