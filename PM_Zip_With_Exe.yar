rule PM_Zip_With_Exe
{
meta:
	author="R.Tokazowski"
	company="PhishMe, Inc."
	URL="http://phishme.com/two-attacks-two-dyres-infrastructure/"
	
strings:
	$hdr = "PK"
	
	$e1 = ".exe" nocase
	$e2 = ".scr" nocase

	
condition:
	$hdr at 0 and (($e1 in (filesize-100..filesize)) or ($e2 in (filesize-100..filesize)))
}