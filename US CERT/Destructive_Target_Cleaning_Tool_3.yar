rule Destructive_Target_Cleaning_Tool_3

{
	meta:
		author = "US CERT"
		reference = "https://www.us-cert.gov/ncas/alerts/TA14-353A"

	strings:

		$S1_CMD_Arg = "/install" fullword
		//$S2_CMD_Parse= ""\""%s'"'  /install \""%s\""'"' fullword
		//$S3_CMD_Builder= ""\'"'%s\""  \""%s\'"' \""%s\'"' %s'"' fullword

condition:

all of them
}