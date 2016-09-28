rule TinyZBot
{

	meta:
		reference = "https://cdn2.hubspot.net/hubfs/270968/assets/Cleaver/Cylance_Operation_Cleaver_Report.pdf"

	strings:
    	$s1 = "NetScp" wide
    	$s2 = "TinyZBot.Properties.Resources.resources"
    	$s3 = "Aoao WaterMark"
    	$s4 = "Run_a_exe"
    	$s5 = "netscp.exe"
    	$s6 = "get_MainModule_WebReference_DefaultWS"
    	$s7 = "remove_CheckFileMD5Completed"
   		$s8 = "http://tempuri.org/"
    	$s9 = "Zhoupin_Cleaver"
    
	condition:
    	($s1 and $s2) or ($s3 and $s4 and $s5) or ($s6 and $s7 and $s8) or $s9
    }