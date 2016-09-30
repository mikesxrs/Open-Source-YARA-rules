rule TrojanPSWTepferSample
{
	meta:
		Description  = "Trojan.Tepfer.sm"
		ThreatLevel  = "5"

	strings:
		$ = "Software\\BPFTP"                                    ascii wide
		$ = "\\BulletProof Software\\BulletProof FTP Client"     ascii wide
		$ = "Software\\BPFTP\\Bullet Proof FTP"                  ascii wide
		$ = "Software\\NCH Software\\ClassicFTP\\FTPAccounts"    ascii wide
		$ = "\\GlobalSCAPE\\CuteFTP"                             ascii wide
		$ = "\\GlobalSCAPE\\CuteFTP Pro"                         ascii wide
		$ = "\\GlobalSCAPE\\CuteFTP Lite"                        ascii wide
		$ = "\\CuteFTP"                                          ascii wide
		$ = "\\GPSoftware\\Directory Opus\\ConfigFiles\\ftp.oxc" ascii wide
		$ = "SOFTWARE\\Far\\Plugins\\FTP\\Hosts"                 ascii wide
		$ = "SOFTWARE\\Far2\\Plugins\\FTP\\Hosts"                ascii wide
		$ = "Software\\Far\\Plugins\\FTP\\Hosts"                 ascii wide
		$ = "Software\\Far2\\Plugins\\FTP\\Hosts"                ascii wide
		$ = "Software\\Far\\SavedDialogHistory\\FTPHost"         ascii wide
		$ = "Software\\Far2\\SavedDialogHistory\\FTPHost"        ascii wide
		$ = "Software\\Ghisler\\Windows Commander"				 ascii wide
		$ = "Software\\Ghisler\\Total Commander"				 ascii wide
		$ = "Software\\Sota\\FFFTP"                              ascii wide
		$ = "Software\\FileZilla"                                ascii wide
		$ = "FileZilla3"                                         ascii wide
		$ = "FlashFXP"                                           ascii wide
		$ = "FTP Commander Pro"                                  ascii wide
		$ = "FTP Navigator"                                      ascii wide
		$ = "FTP Commander"                                      ascii wide
		$ = "FTP Commander Deluxe"                               ascii wide
		$ = "Software\\FTP Explorer\\Profiles"                   ascii wide
		$ = "\\FTP Explorer\\profiles.xml"                       ascii wide
		$ = "Windows/Total Commander"                            ascii wide
		$ = "FTP Commander"                                      ascii wide
		$ = "BulletProof FTP Client"                             ascii wide
		$ = "TurboFTP"                                           ascii wide
		$ = "SoftX FTP Client"                                   ascii wide
		$ = "LeapFTP"                                            ascii wide
		$ = "WinSCP"                                             ascii wide
		$ = "32bit FTP"                                          ascii wide
		$ = "FTP Control"                                        ascii wide
		$ = "SecureFX"                                           ascii wide
		$ = "BitKinex"                                           ascii wide
		$ = "CuteFTP"                                            ascii wide
		$ = "WS_FTP"                                             ascii wide
		$ = "FFFTP"                                              ascii wide
		$ = "Core FTP"                                           ascii wide
		$ = "WebDrive"                                           ascii wide
		$ = "Classic FTP"                                        ascii wide
		$ = "Fling"                                              ascii wide
		$ = "NetDrive"                                           ascii wide
		$ = "FileZilla"                                          ascii wide
		$ = "FTP Explorer"                                       ascii wide
		$ = "SmartFTP"                                           ascii wide
		$ = "FTPRush"                                            ascii wide
		$ = "UltraFXP"                                           ascii wide
		$ = "Frigate3 FTP"                                       ascii wide
		$ = "BlazeFtp"				ascii wide
		$ = "Software\\LeechFTP"	ascii wide
		$ = "SiteInfo.QFP"			ascii wide
		$ = "WinFTP"				ascii wide
		$ = "FreshFTP"				ascii wide
		$ = "BlazeFtp"				ascii wide
	condition:
		9 of them
}