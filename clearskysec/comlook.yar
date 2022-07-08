import "pe"

rule apt_RU_turla_comlook
{
	meta:
		date="20/01/22"
		Author = "ClearSky Cybersecurity"
		TLP = "WHITE"
	
	strings:

		$a1 = "\x00Server switched.\x00" 
		$a2 = "\x00Message handling error!\x00" 
		$a3 = "\x00Incorrect username in IMAP request.\x00"
		$a4 = "\x00Incorrect password in IMAP request.\x00"
		$a5 = "atexit failed to register curl_global_cleanup.\x00"
		$a6 = "curl FetchMessagePart failed."
		$a7 = "curl PerformQuery failed."
		$a8 = "curl SendResult failed."
		$a9 = "Cannot copy data for sending buffer."
		$a10 = "Initialization of libcurl has failed."
		$a11 = "COULDN'T OPEN PIPES TO RECEIVE EXECUTION RESULT\x00"
		$a12 = "OPERATION PERFORMED SUCCESSFULLY WITHOUT WAITING FOR RESULT\x00"
		$a13 = "OPERATION PERFORMED SUCCESSFULLY WITH NULL RESULT.\x00"
		$a14 = "COMMAND IS EMPTY.\x00"
		$a15 = "Antispam Marisuite for The Bat!"
		$a16 = "\x00CMD_EXECUTION_PIPE_OPEN_ERROR\x00"
		$a17 = "\x00CONFIG_LAST_COMMAND_DATE_REG_WRITE_ERROR\x00"
		$a18 = "\x00IMAP_MAILSERVER_FORMAT_INCORRECT\x00"
		$a19 = "\x00GET_UIDS_TO_CHECK_PARSING_ERROR\x00"
		
		$b1 = "\x00SEARCH UID \x00"
		$b2 = "\x00 +FLAGS \\Deleted\x00"
		$b3 = "\x00UID SEARCH SENTSINCE \x00"
		$b4 = "Software\\RIT\\The Bat!\x00" wide 

	condition:
		filesize < 10MB and uint16(0) == 0x5A4D and
		(
			pe.imphash() == "ee4ac9f3c15a225a117392a01b78686e" or
			2 of ($a*) or
			3 of ($b*) or
			(
				pe.imports("TBP_Intialize") and
				any of ($a*)
			)
		)
}
