rule TrojanSpyWin32UrsnifASample
{
	meta:
		Description  = "Trojan.Ursnif.sm"
		ThreatLevel  = "5"

	strings:
		$ = "CreateProcessNotify" ascii wide
		$ = "rundll32" ascii wide
		$ = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" ascii wide
		$ = "System\\CurrentControlSet\\Control\\Session Manager\\AppCertDlls" ascii wide
		$ = "iexplore.exe" ascii wide
		$ = "firefox.exe" ascii wide
		$ = "Software\\AppDataLow\\Software\\Microsoft\\Internet Explorer\\Security\\AntiPhishing" ascii wide
		$ = "/UPD" ascii wide
		$ = "/sd %lu" ascii wide
		$ = "%lu.bat" ascii wide
		$ = "attrib -r -s -h %%1" ascii wide
		$ = "S:(ML;;NW;;;LW)" ascii wide
		$ = "D:(D;OICI;GA;;;BG)(D;OICI;GA;;;AN)(A;OICI;GA;;;AU)(A;OICI;GA;;;BA)" ascii wide
		$ = "%lu.exe" ascii wide                                                                                                                                                         
		$ = "mashevserv.com" ascii wide                                                                       
		$ = "ericpotic.com" ascii wide                                                                                                                                                                                                                             
		$ = "version=%u&user=%x%x%x%x&server=%u&id=%u&crc=%x&aid=%u" ascii wide                                                                                                       
		$ = "CHROME.DLL" ascii wide                                                                                                                                                                                                                                   
		$ = "chrome.exe" ascii wide                                                                            
		$ = "opera.exe"  ascii wide                                                                            
		$ = "safari.exe" ascii wide                                                                            
		$ = "explorer.exe" ascii wide

	condition:
		6 of them
}