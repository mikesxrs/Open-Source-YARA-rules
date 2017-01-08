rule solarbot{
    meta:
        author = "Brian Wallace @botnet_hunter"
        author_email = "bwall@ballastsecurity.net"
        date = "2015-03-21"
        description = "Identify Solar"
    strings:
        $str1 = "v=%d.%d&u=%s&c=%s&s=%s&w=%d.%d.%d&b=%d"
    condition:
        all of them
}