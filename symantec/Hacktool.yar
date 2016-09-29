rule Hacktool 
{ 
	meta: 
		author = "Symantec Security Response"
		date = "2015-07-01" 
		description = "Butterfly hacktool"
		reference = "https://www.symantec.com/content/en/us/enterprise/media/security_response/whitepapers/butterfly-corporate-spies-out-for-financial-gain.pdf"

	strings: 
		$str_1 = "\\\\.\\pipe\\winsession" wide 
		$str_2 = "WsiSvc" wide 
		$str_3 = "ConnectNamedPipe"
		$str_4 = "CreateNamedPipeW" 
		$str_5 = "CreateProcessAsUserW"
        
	condition: 
		all of them 
}