rule SHA256_Constants {
        meta:
                author = "phoul (@phoul)"
                description = "Look for SHA224/SHA256 constants"
                date = "2014-01"
                version = "0.1"
        strings:
		$c0 = { 428a2f98 }
		$c1 = { 982F8A42 }
		$c2 = { 71374491 }
		$c3 = { 91443771 }
		$c4 = { B5C0FBCF }
		$c5 = { CFFBC0B5 }
		$c6 = { E9B5DBA5 }
		$c7 = { A5DBB5E9 }
		// Exclude
		$e0 = { D728AE22 }
		$e1 = { 22AE28D7 }
	condition:
                4 of ($c0,$c1,$c2,$c3,$c4,$c5,$c6,$c7) and not ($e0 or $e1)
}