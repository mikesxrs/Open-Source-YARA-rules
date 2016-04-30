rule Havex_Trojan_PHP_Server
	{
	meta:
		description = "Detects the PHP server component of the Havex RAT"
		date = "2014-06-24"
		author = "Florian Roth"
		reference = "http://goo.gl/GO5mB1"
	strings:
	    $s1 = "havex--></body></head>"
		$s2 = "ANSWERTAG_START"
		$s3 = "PATH_BLOCKFILE"
	condition:
	    all of them
}