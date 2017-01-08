rule BlackShadesServer{
    meta:
        author = "Brian Wallace @botnet_hunter"
        author_email = "bwall@ballastsecurity.net"
        date = "2014-08-16"
        description = "Identify BlackShadesServer"
    strings:
        $str1 = "bss_server"
        $str2 = "txtChat"
        $str3 = "UDPFlood"
    condition:
        all of them
}