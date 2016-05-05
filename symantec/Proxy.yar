rule Proxy
{
	 meta:
		 author = “Symantec Security Response”
		 date = “2015-07-01”
		 description = “Butterfly proxy hacktool”
		 reference = "https://www.symantec.com/content/en/us/enterprise/media/security_response/whitepapers/butterfly-corporate-spies-out-for-financial-gain.pdf"

	 strings:
		 $str _ 1 = “-u user : proxy username”
		 $str _ 2 = “--pleh : displays help”
		 $str _ 3 = “-x ip/host : proxy ip or host”
		 $str _ 4 = “-m : bypass mutex check”
	 condition:
		 all of them
 }