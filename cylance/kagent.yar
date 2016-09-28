rule kagent
{
	meta:
		reference = "https://cdn2.hubspot.net/hubfs/270968/assets/Cleaver/Cylance_Operation_Cleaver_Report.pdf"

 	strings:
 		$s1 = "kill command is in last machine, going back"
 		$s2 = "message data length in B64: %d Bytes"
 		
 	condition:
 		all of them
}