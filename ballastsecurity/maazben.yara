rule maazben
{
    meta:
        author = "Brian Wallace @botnet_hunter"
        author_email = "bwall@ballastsecurity.net"
        date = "2014-03-13"
        description = "Identify Maazben"
    strings:
        $encrypted1 = {d4 2a 47 00 44 6d 47 00}
        $encrypted2 = "__CxxFrameHandler"
        $str1 = "Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 5.1; .NET CLR 1.1.4322; .NET CLR 2.0.50728)"
        $str2 = "%s\\Software\\Microsoft\\Windows\\CurrentVersion\\Ext\\Stats"
        $str3 = "MCIDRV_VER"
    condition:
        ($encrypted1 and $encrypted2) or ($str1 and $str2 and $str3)
}