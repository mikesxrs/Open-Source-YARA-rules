rule SynFlooder
{
	meta:
		reference = "https://cdn2.hubspot.net/hubfs/270968/assets/Cleaver/Cylance_Operation_Cleaver_Report.pdf"

	strings:
    	$s1 = "Unable to resolve [ %s ]. ErrorCode %d"
    	$s2 = "your target's IP is : %s"
   		$s3 = "Raw TCP Socket Created successfully."
        
	condition:
    	all of them
}