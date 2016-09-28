rule sakula_v1_3
{
    meta:
        description = "Sakula v1.3"
        date = "2015-10-13"
        author = "Airbus Defence and Space Cybersecurity CSIRT - Yoann Francou"
        reference = "http://blog.airbuscybersecurity.com/post/2015/09/APT-BlackVine-Malware-Sakula"
    strings:
        $m1 = "%d_of_%d_for_%s_on_%s"
        $m2 = "/c ping 127.0.0.1 & del /q \"%s\""
        $m3 = "cmd.exe /c rundll32 \"%s\""

        $v1_3 = { 81 3E 78 03 00 00 75 57  8D 54 24 14 52 68 0C 05 41 00 68 01 00 00 80 FF  15 00 F0 40 00 85 C0 74 10 8B 44 24 14 68 2C 31  41 00 50 FF 15 10 F0 40 00 8B 4C 24 14 51 FF 15  24 F0 40 00 E8 0F 09 00 }

        $MZ = "MZ"
    condition:
        $MZ at 0 and all of them
}