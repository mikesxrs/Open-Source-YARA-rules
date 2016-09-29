rule Trojan_Karagany
{
	meta:
		alias = "Dreamloader"
		Author = "Symantec"
		Reference = "https://www.symantec.com/content/en/us/enterprise/media/security_response/whitepapers/Dragonfly_Threat_Against_Western_Energy_Suppliers.pdf"

	strings:
		$s1 = "neosphere" wide ascii
		$s2 = "10000000000051200" wide ascii
		$v1 = "&fichier" wide ascii
		$v2 = "&identifiant" wide ascii
		$c1 = "xmonstart" wide ascii
		$c2 = "xmonstop" wide ascii
		$c3 = "xgetfile" wide ascii
		$c4 = "downadminexec" wide ascii
		$c5 = "xdiex" wide ascii
		$c6 = "xrebootx" wide ascii

	condition:
		isPE and (($s1 and $s2) or ($v1 and $v2) or (any of ($c*)))
}