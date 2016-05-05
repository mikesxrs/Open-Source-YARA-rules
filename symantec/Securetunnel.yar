rule Securetunnel
{
 	meta:
		 author = “Symantec Security Response”
		 date = “2015-07-01”
		 description = “Butterfly Securetunnel hacktool”
		 reference = "https://www.symantec.com/content/en/us/enterprise/media/security_response/whitepapers/butterfly-corporate-spies-out-for-financial-gain.pdf"


	 strings:
		 $str _ 1 = “KRB5CCNAME”
		 $str _ 2 = “SSH _ AUTH _ SOCK”
		 $str _ 3 = “f:l:u:cehR”
 		 $str _ 4 = “.o+=*BOX@%&#/^SE”
	 condition:
		 all of them
}