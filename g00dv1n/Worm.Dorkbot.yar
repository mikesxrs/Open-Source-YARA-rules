rule WormWin32DorkbotSamlpeA
{
 meta:
  Description  = "Worm.Dorkbot.sm"
  ThreatLevel  = "5"

 strings:
	$ = "from removing our bot file!" ascii wide
	$ = "from moving our bot file" ascii wide
	$ = "Message hijacked!" ascii wide
	$ = "popgrab" ascii wide
	$ = "ftpgrab" ascii wide
	$ = "s.Blocked possible browser exploit pack call on URL" ascii wide
	$ = "webroot." ascii wide
	$ = "fortinet." ascii wide
	$ = "virusbuster.nprotect." ascii wide
	$ = "gdatasoftware." ascii wide
	$ = "virus." ascii wide
	$ = "precisesecurity." ascii wide
	$ = "lavasoft." ascii wide
	$ = "heck.tc" ascii wide
	$ = "emsisoft." ascii wide
	$ = "onlinemalwarescanner." ascii wide
	$ = "onecare.live." ascii wide
	$ = "f-secure." ascii wide
	$ = "bullguard." ascii wide
	$ = "clamav." ascii wide
	$ = "pandasecurity." ascii wide
	$ = "sophos." ascii wide
	$ = "malwarebytes." ascii wide
	$ = "sunbeltsoftware." ascii wide
	$ = "norton." ascii wide
	$ = "norman." ascii wide
	$ = "mcafee." ascii wide
	$ = "symantec" ascii wide
	$ = "comodo." ascii wide
	$ = "avast." ascii wide
	$ = "avira." ascii wide
	$ = "avg." ascii wide
	$ = "bitdefender." ascii wide
	$ = "eset." ascii wide
	$ = "kaspersky." ascii wide
	$ = "trendmicro." ascii wide
	$ = "iseclab." ascii wide
	$ = "virscan." ascii wide
	$ = "garyshood." ascii wide
	$ = "viruschief." ascii wide
	$ = "jotti." ascii wide
	$ = "threatexpert." ascii wide
	$ = "novirusthanks." ascii wide
	$ = "virustotal." ascii wide
	$ = "you stupid cracker" ascii wide
	$ = "ngrBot Error" ascii wide
	$ = "Slowloris]: Finished flood on" ascii wide
	$ = "UDP]: Finished flood on" ascii wide
	$ = "SYN]: Finished flood on" ascii wide
	$ = "USB]: Infected %s" ascii wide
	$ = "MSN]: Updated MSN spread message to" ascii wide
	$ = "MSN]: Updated MSN spread interval to" ascii wide
	$ = "HTTP]: Updated HTTP spread message to" ascii wide
	$ = "HTTP]: Injected value is now %s." ascii wide
	$ = "HTTP]: Updated HTTP spread interval to" ascii wide
	$ = "Visit]: Visited" ascii wide
	$ = "DNS]: Blocked" ascii wide
	$ = "RSOCK4]: Started rsock4" ascii wide
	$ = "Visit]: Error visitng" ascii wide
	$ = "FTP Login]: %s" ascii wide
	$ = "POP3 Login]: %s" ascii wide
	$ = "FTP Infect]: %s was iframed" ascii wide
	$ = "HTTP Login]: %s" ascii wide
	$ = "HTTP Traffic]: %s" ascii wide
	$ = "Ruskill]: Detected File:" ascii wide
	$ = "Ruskill]: Detected DNS:" ascii wide
	$ = "Ruskill]: Detected Reg:" ascii wide
	$ = "PDef+]: %s" ascii wide
	$ = "DNS]: Blocked DNS" ascii wide
	$ = "MSN]: %s" ascii wide
	$ = "HTTP]: %s" ascii wide
 condition:
  8 of them
}

rule WormWin32DorkbotSamlpeB
{
 	meta:
 		Description  = "Worm.Dorkbot.sm"
 		ThreatLevel  = "5"

 	strings:
		$ = "http://ht.ly/jZH8A?yd=" ascii wide
		$ = "DecriptedFiles" ascii wide
		$ = "Infected Drive: %s" ascii wide
		$a = "snkb00pt" ascii wide

 	condition:
 		(3 of them) or $a
}