rule Proxy
{ 
	meta: 
		author = "Symantec Security Response"
		date = "2015-07-01"
		description = "Butterfly proxy hacktool" 
		reference = "https://www.symantec.com/content/en/us/enterprise/media/security_response/whitepapers/butterfly-corporate-spies-out-for-financial-gain.pdf"

	strings: 
		$str_1 = "-u user : proxy username" 
		$str_2 = "--pleh : displays help" 
		$str_3 = "-x ip/host : proxy ip or host" 
		$str_4 = "-m : bypass mutex check"
        
	condition: 
		all of them 
}