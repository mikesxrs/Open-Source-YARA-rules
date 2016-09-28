rule sakula_v3_0
{
    meta:
        description = "Sakula v3.0"
        date = "2015-10-13"
        author = "Airbus Defence and Space Cybersecurity CSIRT - Yoann Francou"
        reference = "http://blog.airbuscybersecurity.com/post/2015/10/Malware-Sakula-Evolutions-%28Part-2/2%29"
    strings:
        $m1 = "Mozilla/4.0+(compatible;+MSIE+8.0;+Windows+NT+5.1;+SV1)"
        $m2 = "ry.db"
        $m3 = "cmd.exe /c reg add %s\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v \"%s\" /t REG_SZ /d \"%s\""
        $m4 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run"

        $MZ = "MZ"
    condition:
        $MZ at 0 and all of them
}


