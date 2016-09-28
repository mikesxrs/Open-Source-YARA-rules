rule sakula_v2_1
{
    meta:
        description = "Sakula v2.1"
        date = "2015-10-13"
        author = "Airbus Defence and Space Cybersecurity CSIRT - Yoann Francou"
        reference = "http://blog.airbuscybersecurity.com/post/2015/10/Malware-Sakula-Evolutions-%28Part-2/2%29"
    strings:
        $m1 = "Sakula"
        $m2 = "%d_of_%d_for_%s_on_%s"
        $m3 = "Create Child Cmd.exe Process Succeed!"
        $v2_1 = "\\drivers\\etc\\hosts"

        $MZ = "MZ"
    condition:
        $MZ at 0 and all of them
}
