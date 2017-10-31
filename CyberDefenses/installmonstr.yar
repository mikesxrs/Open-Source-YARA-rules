rule installmonstr {
meta:
		description = "adware, trojan, riskware"
		author = "Monty St John"
		company = "Cyberdefenses, inc."
		date = "2017/01/25"
		hash1 = "000be3b9991eaf28b3794d96ce08e883"
		hash2 = "1c21a4b1151921398b2c2fe9ea9892f8"
		hash3 = "be6eb42ea9e789d2a4425f61155f4664"
		hash4 = "001dd4fdd6973f4e6cb9d11bd9ba7eb3"
		
strings:
	$a = "<META HTTP-EQUIV=\"Refresh\" CONTENT=\"0; URL=%0:s\">"
	$b = "%s<input type=\"hidden\" name=\"%s\" value=\"%s\">%s"
	$c = "GoIdHTTPWork"
	$d = "sslvSSLv2sslvSSLv23sslvSSLv3sslvTLSv1"
	$e = "sslvSSLv23	sslvSSLv3	sslvTLSv1"
	$f = "AES:ALL:!aNULL:!eNULL:+RC4:@STRENGTH"

condition:
  5 of them 
}
