rule WormWin32CridexSamlpeE
{
	meta:
		Description  = "Worm.Cridex.sm"
		ThreatLevel  = "5"

	strings:
		$ = "Software\\Microsoft\\Windows NT\\C%08X" ascii wide   
		$ = "<server><![CDATA[%%u.%%u.%%u.%%u:%%u]]>" ascii wide
		$ = "KB%08d.exe" ascii wide
		$ = "Local\\XME%08X" ascii wide
		$ = "Local\\XMM%08X" ascii wide
		$ = "Local\\XMI%08X" ascii wide
		$ = "Local\\XMS%08X" ascii wide                                                                                                     
		$ = "Local\\XMF%08X" ascii wide                                                                                                                                                                                                              
		$ = "Local\\XMR%08X" ascii wide                                                                                                                                                                                                        
		$ = "Local\\XMQ%08X" ascii wide                                                                                                     
		$ = "Local\\XMB%08X" ascii wide 
	condition:
		2 of them
}