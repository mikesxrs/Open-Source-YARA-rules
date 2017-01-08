rule backoff {
    meta:
        author = "Brian Wallace @botnet_hunter"
        author_email = "bwall@ballastsecurity.net"
        date = "2014-08-21"
        description = "Identify Backoff"
	strings:
    	$s1 = "&op=%d&id=%s&ui=%s&wv=%d&gr=%s&bv=%s"
        $s2 = "%s @ %s"
        $s3 = "Upload KeyLogs"
    condition:
        all of them
}