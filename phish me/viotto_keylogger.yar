rule viotto_keylogger
{
meta:
	author = "Paul B. (@hexlax) PhishMe Research"
	description = "Matches unpacked Viotto Keylogger samples"
	details "http://phishme.com/viotto-keylogger"

strings:
	$hdr = "MZ"
	$s1 = "Viotto Keylogger"
	$s2 = "msvbvm60"
	$s3 = "FtpPutFileA"
	$s4 = "VBA6"
	$s5 = "SetWindowsHookExA"
condition:
	($hdr at 0) and all of ($s*)

}