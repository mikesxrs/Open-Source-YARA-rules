rule sakula_v1_2
{
    meta:
        description = "Sakula v1.2"
        date = "2015-10-13"
        author = "Airbus Defence and Space Cybersecurity CSIRT - Yoann Francou"
        reference = "http://blog.airbuscybersecurity.com/post/2015/09/APT-BlackVine-Malware-Sakula"
    strings:
        $m1 = "%d_of_%d_for_%s_on_%s"
        $m2 = "/c ping 127.0.0.1 & del /q \"%s\""
        $m3 = "cmd.exe /c rundll32 \"%s\""
        $v1_1 = "MicroPlayerUpdate.exe"
        $v1_2 = "CCPUpdate"

        $MZ = "MZ"
    condition:
        $MZ at 0 and $m1 and $m2 and $m3 and $v1_2 and not $v1_1
}
