rule TrojanWin32Vawtrak_BackDoor
{
	meta:
		Description  = "Backdoor.Win32.sm"
		ThreatLevel  = "5"

	strings:
		$ = "[VNC] New Client" ascii wide
		$ = "[VNC] Fail init BC" ascii wide
		$ = "[VNC] Fail addr proto BC" ascii wide
		$ = "[VNC] Fail connect BC" ascii wide
		$ = "[VNC] Fail init work:" ascii wide
		$ = "[VNC] Start Sever" ascii wide
		$ = "[VNC] Parse param error:" ascii wide
		$ = "[VNC] Fail create  process:" ascii wide
		$ = "[VNC] Fail inject to process:" ascii wide
		$ = "[Socks] New Client" ascii wide
		$ = "[Socks] Failt Init BC" ascii wide
		$ = "[Socks] Fail add proto BC" ascii wide
		$ = "[Socks] Failt connect BC" ascii wide
		$ = "[Socks] Fail parse param:" ascii wide
		$ = "[Pony] Fail Get Pass" ascii wide
		$ = "DL_EXEC Status [Pipe]" ascii wide
		$ = "DL_EXEC Status[Local]" ascii wide
		$ = "Start Socks addr:" ascii wide
		$ = "Start Socks Status[Pipe]" ascii wide
		$ = "Start Socks Status[Local]" ascii wide
		$ = "Start VNC addr: %s" ascii wide
		$ = "Start VNC Status[Pipe]: %u-%u-%u" ascii wide
		$ = "Start VNC Status[Local]: %u" ascii wide
		$ = "PID: %u [%0.2u:%0.2u:%0.2u]" ascii wide
		$ = "[BC] Cmd Ver Error" ascii wide
		$ = "[BC] Wait Ping error %u[%u]" ascii wide
		$ = "[BC] Fail Connect" ascii wide
		$ = "[BC] Fail send auth" ascii wide
		$ = "[BC] Fail read cmd" ascii wide
		$ = "[BC] cmd error: %u" ascii wide
		$ = "[BC] Cmd need disconnect" ascii wide
		$ = "SELECT hostname, encryptedUsername, encryptedPassword FROM moz_logins" ascii wide
		
		$str_0 = "T:\\Develop\\EQ2\\bin\\tmp" ascii wide
		$str_1 = "T:\\Develop\\EQ2\\bin\\tmp\\client_32.pdb" ascii wide
		$str_2 = "T:\\Develop\\EQ2\\bin\\tmp\\client_64.pdb" ascii wide
		$str_3 = "client_64.dll" ascii wide   
		$str_4 = "client_32.dll" ascii wide

	condition:
		(5 of them) or (any of ($str_*))
}
