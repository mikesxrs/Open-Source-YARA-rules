rule Xtreme
{
    meta:
        author = "Brian Wallace @botnet_hunter (with combination of work from Kevin Breen)"
        author_email = "bwall@ballastsecurity.net"
        date = "2015-03-25"
        description = "Identify XtremeRat"
    strings:
        $s1 = "XTREME" wide
        $s2 = "XTREMEBINDER" wide
        $s3 = "DVCLAL" wide
        $s4 = "PACKAGEINFO" wide
        $s5 = "XTREMEUPDATE" wide
        
        $a1 = "XTREME" wide
        $a2 = "ServerStarted" wide
        $a3 = "XtremeKeylogger" wide
        $a4 = "x.html" wide
        $a5 = "Xtreme RAT" wide
    condition:
        all of ($s*) or all of ($a*)
}