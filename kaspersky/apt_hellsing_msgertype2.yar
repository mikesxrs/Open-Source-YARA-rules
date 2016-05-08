rule apt_hellsing_msgertype2 
{
	meta:
		version = "1.0"
		filetype = "PE"
		author = "Costin Raiu, Kaspersky Lab"
		copyright = "Kaspersky Lab"
		date = "2015-04-07"
		description = "detection for Hellsing msger type 2 implants"
	strings:
		$mz="MZ"
		$a1="%s\\system\\%d.txt"
		$a2="_msger"
		$a3="http://%s/lib/common.asp?action=user_login&uid=%s&lan=%s&host=%s&os=%s&proxy=%s"
		$a4="http://%s/data/%s.1000001000"
		$a5="/lib/common.asp?action=user_upload&file="
		$a6="%02X-%02X-%02X-%02X-%02X-%02X"

	condition:
		($mz at 0) and (4 of ($a*)) and filesize < 500000
		
}