rule Cadelle_2
{
meta:
	author = "Symantec"
	reference = "http://www.symantec.com/content/en/us/enterprise/media/security_response/docs/CadelSpy-Remexi-IOC.pdf"
strings:
	$s1  = "[EXECUTE]" wide ascii
	$s2  = "WebCamCapture" wide ascii
	$s3  = "</DAY>" wide ascii
	$s4  ="</DOCUMENT>" wide ascii
	$s5  = "<DOCUMENT>" wide ascii
	$s6  = "<DATETIME>" wide ascii
	$s7  = "Can't open file for reading :" wide ascii
	$s8  = "</DATETIME>" wide ascii
	$s9  = "</USERNAME>" wide ascii
	$s10 = "JpegFile :" wide ascii
	$s12 = "[SCROLL]" wide ascii
	$s13 = "<YEAR>" wide ascii
	$s14 = "CURRENT DATE" wide ascii
	$s15 = "</YEAR>" wide ascii
	$s16 = "</MONTH>" wide ascii
	$s17 = "<PRINTERNAME>" wide ascii
	$s18 = "</DRIVE>" wide ascii
	$s19 = "<DATATYPE>" wide ascii
	$s20 = "<MACADDRESS>" wide ascii
	$s21 = "FlashMemory" wide ascii
condition:
	12 of them
}

