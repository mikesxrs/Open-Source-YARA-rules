rule DarkComet
{
￼￼meta:
	description = "DarkComet RAT"
	author = "Fidelis Cybersecurity"
	reference = "Fidelis Threat Advisory #1018 - Looking at the Sky for a DarkComet - August 4, 2015"
	date = "2015-07-22" 

strings:
	$s1 = "#KCMDDC"
	$s2 = "DCDATA"
	$s3 = "#BOT#CloseServer" 
	$s4 = "#BOT#SvrUninstall"
	$s5 = "#BOT#URLDownload" 
condition:
	uint16(0) == 0x5a4d and filesize < 50MB and all of ($s*)
}

