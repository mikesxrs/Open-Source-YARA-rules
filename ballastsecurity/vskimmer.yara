rule vskimmer {
    meta:
        author = "Brian Wallace @botnet_hunter"
        author_email = "bwall@ballastsecurity.net"
        date = "2014-09-02"
        description = "Identify vSkimmer"
	strings:
    	$s1 = "User-Agent: PCICompliant/3.33"
        $s2 = "[3-9]{1}[0-9]{12,19}[D=\\u0061][0-9]{10,30}"
        $s3 = "PCI Compliant SCard"
    condition:
        all of them
}
