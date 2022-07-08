rule ContiV2 {
	meta:
	  	description = "YARA rule for Conti Ransomware v2"
		reference = "http://chuongdong.com/reverse%20engineering/2020/12/15/ContiRansomware/"
		author = "@cPeterr"
    		date = "2020-12-15"
    		rule_version = "v2"
    		malware_type = "ransomware"
    		malware_family = "Ransom:W32/Conti"
		tlp = "white"
	strings:
		$str1 = "polzarutu1982@protonmail.com"
		$str2 = "http://m232fdxbfmbrcehbrj5iayknxnggf6niqfj6x4iedrgtab4qupzjlaid.onion"
    		$str3 = "expand 32-byte k"
		$string_decryption = { 8a 07 8d 7f 01 0f b6 c0 b9 ?? 00 00 00 2b c8 6b c1 ?? 99 f7 fe 8d 42 7f 99 f7 fe 88 57 ff }
    		$compare_size = { ?? ?? 00 00 50 00 }
	condition:
		all of ($str*) and $string_decryption and $compare_size
}
