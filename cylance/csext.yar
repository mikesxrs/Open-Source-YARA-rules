rule csext
{
	meta:
		reference = "https://cdn2.hubspot.net/hubfs/270968/assets/Cleaver/Cylance_Operation_Cleaver_Report.pdf"

 	strings:
 		$s1 = "COM+ System Extentions"
 		$s2 = "csext.exe"
 		$s3 = "COM_Extentions_bin"
 	condition:
 		all of them
}