rule mimikatzWrapper
{
	meta:
		reference = "https://cdn2.hubspot.net/hubfs/270968/assets/Cleaver/Cylance_Operation_Cleaver_Report.pdf"

 	strings:
 		$s1 = "mimikatzWrapper"
 		$s2 = "get_mimikatz"
 		
 	condition:
 		all of them
}