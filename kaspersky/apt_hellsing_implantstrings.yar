rule apt_hellsing_implantstrings 
{
	meta:
		version = "1.0"
		filetype = "PE"
		author = "Costin Raiu, Kaspersky Lab"
		copyright = "Kaspersky Lab"
		date = "2015-04-07"
		description = "detection for Hellsing implants"

	strings:
 		$mz="MZ"
 		$a1="the file uploaded failed !"
 		$a2="ping 127.0.0.1"
 		$b1="the file downloaded failed !"
 		$b2="common.asp"
 		$c="xweber_server.exe"
 		$d="action="
		$debugpath1="d:\\Hellsing\\release\\msger\\" nocase
		$debugpath2="d:\\hellsing\\sys\\xrat\\" nocase
		$debugpath3="D:\\Hellsing\\release\\exe\\" nocase
		$debugpath4="d:\\hellsing\\sys\\xkat\\" nocase
		$debugpath5="e:\\Hellsing\\release\\clare" nocase
		$debugpath6="e:\\Hellsing\\release\\irene\\" nocase
		$debugpath7="d:\\hellsing\\sys\\irene\\" nocase
		$e="msger_server.dll"
		$f="ServiceMain"

	condition:
		($mz at 0) and (all of ($a*)) or (all of ($b*)) or ($c and $d) or (any of ($debugpath*)) or ($e and $f) and filesize < 500000
}