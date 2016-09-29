rule Eventlog 
{ 
	meta: 
		author = "Symantec Security Response"
		date = "2015-07-01" 
		description = "Butterfly Eventlog hacktool"
 		reference = "https://www.symantec.com/content/en/us/enterprise/media/security_response/whitepapers/butterfly-corporate-spies-out-for-financial-gain.pdf"

	strings: 
		$str_1= "wevtsvc.dll"
		$str_2= "Stealing %S.evtx handle ..."
		$str_3= "ElfChnk"
		$str_4= "-Dr Dump all logs from a channel or .evtx file (raw"

	condition: 
		all of them 
}