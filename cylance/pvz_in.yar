rule pvz_in
{
	meta:
		reference = "https://cdn2.hubspot.net/hubfs/270968/assets/Cleaver/Cylance_Operation_Cleaver_Report.pdf"

 	strings:
 		$s1 = "LAST_TIME=00/00/0000:00:00PM$"
 		$s2 = "if %%ERRORLEVEL%% == 1 GOTO line"
 		
 	condition:
 		all of them
}