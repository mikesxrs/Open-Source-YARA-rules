rule BackdoorWin32FynloskiASample
{
	meta:
		Description  = "Backdoor.Fynloski.sm"
		ThreatLevel  = "5"

	strings:
		$ = "#BOT#VisitUrl" ascii wide
		$ = "#BOT#OpenUrl" ascii wide
		$ = "#BOT#Ping" ascii wide
		$ = "BTRESULTPing|Res" ascii wide
		$ = "#BOT#RunPrompt" ascii wide
		$ = "BTRESULTClose" ascii wide
		$ = "#BOT#SvrUninstal" ascii wide
		$ = "#BOT#URLUpdate" ascii wide
		$ = "BTERRORUpdate" ascii wide
		$ = "BTRESULTUpdate" ascii wide
		$ = "#BOT#URLDownload" ascii wide
		$ = "BTRESULTOpen" ascii wide
		$ = "BTERRORDownload" ascii wide
		$ = "BTRESULTDownload" ascii wide
		$ = "BTRESULTMass" ascii wide
		$ = "BTRESULTHTTP" ascii wide
		$ = "BTERRORVisit" ascii wide
		$ = "BTRESULTSyn" ascii wide
		$ = "BTRESULTUDP" ascii wide
		$ = "Flood|UDP Flood task finished" ascii wide
		$ = "Flood|Syn task finished" ascii wide
		$ = "Flood|Http Flood task finished" ascii wide

	condition:
		3 of them
}