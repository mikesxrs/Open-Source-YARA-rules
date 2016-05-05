rule acunetix_web_scanner
{
meta:
	author = "@patrickrolsen"
	version = "0.1"
	reference = "Acunetix Web Scanner"
	date = "2013-12-14"
strings:
	$s =   "acunetix_wvs_security_test"
	$s0 =  "testasp.vulnweb.com"
	$s1 =  "GET /www.acunetix.tst"
condition:
	any of ($s*)
}