rule Multipurpose 
{ 
	meta: 
		author = "Symantec Security Response"
		date = "2015-07-01" 
		description = "Butterfly Multipurpose hacktool" 
		reference = "https://www.symantec.com/content/en/us/enterprise/media/security_response/whitepapers/butterfly-corporate-spies-out-for-financial-gain.pdf"
	strings: 
		$str_1 = "dump %d|%d|%d|%d|%d|%d|%s|%d"
		$str_2 = "kerberos%d.dll"
		$str_3 = "\\\\.\\pipe\\lsassp" 
		$str_4 = "pth <PID:USER:DOMAIN:NTLM>: change" 
	condition: 
		all of them 
}