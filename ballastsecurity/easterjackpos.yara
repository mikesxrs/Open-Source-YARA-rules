rule easterjackpos {
    meta:
        author = "Brian Wallace @botnet_hunter"
        author_email = "bwall@ballastsecurity.net"
        date = "2014-09-02"
        description = "Identify JackPOS"
	strings:
	    $s1 = "updateinterval="
        $s2 = "cardinterval="
        $s3 = "{[!17!]}{[!18!]}"
    condition:
        all of them
}
