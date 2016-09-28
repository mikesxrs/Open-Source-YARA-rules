rule pvz_out
{
	meta:
		reference = "https://cdn2.hubspot.net/hubfs/270968/assets/Cleaver/Cylance_Operation_Cleaver_Report.pdf"

	strings:
		$s1 = "Network Connectivity Module" wide
    	$s2 = "OSPPSVC" wide

	condition:
		all of them
}