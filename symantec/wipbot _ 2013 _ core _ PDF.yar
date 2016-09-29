rule wipbot_2013_core_PDF
{
	meta:
		author = "Symantec"
		description = "Trojan.Wipbot 2014 core PDF"
		reference = "https://www.symantec.com/content/en/us/enterprise/media/security_response/whitepapers/waterbug-attack-group.pdf"
 	strings:
 		$PDF = "%PDF-"
 		$a = /\+[A-Za-z]{1}\. _ _ \$\+[A-Za-z]{1}\. _ \$ _ \+/
 		$b = /\+[A-Za-z]{1}\.\$\$\$ _ \+/

 	condition:
 		($PDF at 0) and #a > 150 and #b > 200
}