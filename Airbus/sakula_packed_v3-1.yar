rule sakula_packed_v3_1
{
    meta:
        description = "Sakula v3.1 packed shellcode"
        date = "2015-10-13"
        author = "Airbus Defence and Space Cybersecurity CSIRT - Yoann Francou"
        reference = "http://blog.airbuscybersecurity.com/post/2015/10/Malware-Sakula-Evolutions-%28Part-2/2%29"
    strings:
        $m1 = "AAAA"
        $m2 = "BBBB"
        $m3 = "CCCC"

        $MZ = "MZ"
    condition:
        all of ($m*) and @m1 < @m2 and @m2 < @m3 and $MZ at @m3+4
}

