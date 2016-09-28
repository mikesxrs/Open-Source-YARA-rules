rule SmartCopy2
{
	meta:
		reference = "https://cdn2.hubspot.net/hubfs/270968/assets/Cleaver/Cylance_Operation_Cleaver_Report.pdf"

	strings:
	 $s1 = "SmartCopy2.Properties"
	 $s2 = "ZhuFrameWork"
	 
	condition:
	 all of them
}