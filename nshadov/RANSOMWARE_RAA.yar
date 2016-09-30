rule RANSOMWARE_RAA {

	meta:
		description = "Identifes samples containing JS dropper similar to RAA ransomware."
		author = "nshadov"
		reference = "https://malwr.com/analysis/YmE4MDNlMzk2MjY3NDdlYWE1NzFiOTNlYzVhZTlkM2Y/"
		date = "2016-06-15"
		hash = "535494aa6ce3ccef7346b548da5061a9"
		far = "unknown"
		frr = "unknown"
		
	strings:
		$sp0 = "CryptoJS.AES.decrypt" fullword ascii
		$sp1 = "RAA-SEP" fullword ascii
		$sb0 = "ActiveXObject(\"Scriptlet.TypeLib\")" fullword ascii
		$sb1 = "ActiveXObject(\"Scripting.FileSystemObject\")" fullword ascii
		$sb2 = "WScript.CreateObject(\"WScript.Shell\");" fullword ascii
		
	condition:
		filesize > 10KB and filesize < 800KB and ( (all of ($sp*)) or ( (all of ($sb*)) and 1 of ($sp*) ) )
		
	}