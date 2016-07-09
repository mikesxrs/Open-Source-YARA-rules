rule sakula_v1_4
{
    meta:
        description = "Sakula v1.4"
        date = "2015-10-13"
        author = "Airbus Defence and Space Cybersecurity CSIRT - Yoann Francou"
        reference = "http://blog.airbuscybersecurity.com/post/2015/09/APT-BlackVine-Malware-Sakula"
    strings:
        $m1 = "%d_of_%d_for_%s_on_%s"
        $m2 = "/c ping 127.0.0.1 & del /q \"%s\""
        $m3 = "cmd.exe /c rundll32 \"%s\""

        $v1_4 = { 50 E8 CD FC FF FF 83 C4  04 68 E8 03 00 00 FF D7 56 E8 54 12 00 00 E9 AE  FE FF FF E8 13 F5 FF FF }

        $MZ = "MZ"
    condition:
        $MZ at 0 and all of them
}