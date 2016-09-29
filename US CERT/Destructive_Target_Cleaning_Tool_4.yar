/*
rule Destructive_Target_Cleaning_Tool_4:
{
	meta:
		author = "US CERT"
		reference = "https://www.us-cert.gov/ncas/alerts/TA14-353A"
	
	strings:
		$BATCH_SCRIPT_LN1_0 = "goto x" fullword
		$BATCH_SCRIPT_LN1_1 = "del" fullword
		$BATCH_SCRIPT_LN2_0 = "if exist" fullword
		$BATCH_SCRIPT_LN3_0 = ":x" fullword
		$BATCH_SCRIPT_LN4_0 = "zz%d.bat" fullword

	condition:
		(#BATCH_SCRIPT_LNl_l == 2) and all of them"
}

*/