rule packager_cve2017_11882 {
    meta:
        author = "Rich Warren"
        description = "Attempts to exploit CVE-2017-11882 using Packager"
        reference = "https://github.com/rxwx/CVE-2017-11882/blob/master/packager_exec_CVE-2017-11882.py"
        score = 60
    strings:
	    $header_rtf = "{\\rt" nocase
		
        $font = { 30 61 30 31 30 38 35 61  35 61 }
        $equation = { 45 71 75 61 74 69 6F 6E 2E 33 }
        $package = { 50 61 63 6b 61 67 65 }
        $header_and_shellcode = /03010[0,1][0-9a-fA-F]{108}00/ ascii nocase
    condition:
        all of them and $header_rtf at 0
}
