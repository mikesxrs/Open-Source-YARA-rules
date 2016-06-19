import "pe"

rule trojan_win_possible_dridex {
	meta:
		description = "Possibly Dridex sample"
		author = "hidd3ncod3s@gmail.com"
		date = "2015-12-26"
	strings:
		$s1 = "str" fullword ascii
		$s2 = "SVWATAUAWUH" fullword ascii
		$s3 = {56 57 53 55 81 EC 80 00}
	condition:
		($s2 or $s3) and $s1
}

rule trojan_win_dridex {
	meta:
		description = "Rule to identify Dridex(Dec 2015)"
		author = "hidd3ncod3s@gmail.com"
		date = "2015-12-26"
	strings:
		$s1 = "str" fullword ascii
		$s2 = "mod4" fullword ascii
		$s3 = "list" fullword ascii
		$s4 = "bot" fullword ascii
		$s5 = "mod5" fullword ascii
		$s6 = "SVWATAUAWUH" fullword ascii
		
	condition:
		pe.sections[5].name == ".sdata" and all of ($s*)
}


rule trojan_win_dridex_TM {
	meta:
		description = "Rule to identify Dridex.TM"
		author = "hidd3ncod3s@gmail.com"
		date = "2016-01-09"
	strings:
		$s1 = "str" fullword ascii
		$s2 = "SVWATAUAWUH" fullword ascii
		$mv1 = {0F B6 [6] 0F B6 [6] 0F B6 [6] 0F B6 [6] 0F B7}
		$mv2 = {0F B6 [3] 0F B6 [3] 0F B6 [3] 0F B6 [3] 0F B7}

	condition:
		all of ($s*) and ($mv1 or $mv2)
}
