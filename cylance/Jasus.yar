rule Jasus
{
	meta:
		reference = "https://cdn2.hubspot.net/hubfs/270968/assets/Cleaver/Cylance_Operation_Cleaver_Report.pdf"

 	strings:
 		$s1 = "pcap_dump_open"
 		$s2 = "Resolving IPs to poison..."
 		$s3 = "WARNNING: Gateway IP can not be found"
 		
 	condition:
 		all of them
}