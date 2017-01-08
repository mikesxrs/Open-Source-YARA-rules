rule jackpos {
    meta:
        author = "Brian Wallace @botnet_hunter"
        author_email = "bwall@ballastsecurity.net"
        date = "2014-09-02"
        description = "Identify JackPOS"
	strings:
	    $s1 = "%02X-%02X-%02X-%02X-%02X-%02X"
        $s2 = "/post"
        $s3 = "http://"
        $s4 = "&t2="
        $s5 = "&t1="
        $s6 = "mac="
    condition:
        all of them
}
