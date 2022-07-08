rule BabukRansomware {
	meta:
	  	description = "YARA rule for Babuk Ransomware"
		reference = "http://chuongdong.com/reverse%20engineering/2021/01/03/BabukRansomware/"
		author = "@cPeterr"
		date = "2021-01-03"
		rule_version = "v1"
		malware_type = "ransomware"
		tlp = "white"
	strings:
		$lanstr1 = "-lanfirst"
		$lanstr2 = "-lansecond"
		$lanstr3 = "-nolan"
		$str1 = "BABUK LOCKER"
		$str2 = ".__NIST_K571__" wide
		$str3 = "How To Restore Your Files.txt" wide
		$str4 = "ecdh_pub_k.bin" wide
	condition:
		all of ($str*) and all of ($lanstr*)
}
