rule sakula_v1_0
{
    meta:
        description = "Sakula v1.0"
        date = "2015-10-13"
        author = "Airbus Defence and Space Cybersecurity CSIRT - Yoann Francou"
        reference = "http://blog.airbuscybersecurity.com/post/2015/09/APT-BlackVine-Malware-Sakula"
    strings:
        $m1 = "%d_of_%d_for_%s_on_%s"
        $m2 = "/c ping 127.0.0.1 & del /q \"%s\""
        $m3 = "=%s&type=%d"
        $m4 = "?photoid="
        $m5 = "iexplorer"
                $m6 = "net start \"%s\""
        $v1_1 = "MicroPlayerUpdate.exe"
        $MZ = "MZ"
    condition:
        $MZ at 0 and all of ($m*) and not $v1_1
}