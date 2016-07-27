rule web_log_review
{
meta:
	author = "@patrickrolsen"
	version = "0.1"
	reference = "Key words in weblogs - Very likely FPs in here."
	date = "2013-12-14"
strings:
	$s =   "GET /.htaccess" nocase
	$s0 =  "GET /db/main.php" nocase
	$s3 =  "GET /dbadmin/main.php" nocase
	$s4 =  "GET /phpinfo.php" nocase
	$s5 =  "GET /password" nocase
	$s6 =  "GET /passwd" nocase
	$s7 =  "GET /phpmyadmin2" nocase
	$s8 =  "GET /c99shell.php" nocase
	$s9 =  "GET /c99.php" nocase
	$s10 = "GET /response.write" nocase
	$s11 = "GET /&dir" nocase
	$s12 = "backdoor.php" nocase
	$s13 = "GET /.htpasswd" nocase
	$s14 = "GET /htaccess.bak" nocase
	$s15 = "GET /htaccess.txt" nocase
	$s16 = "GET /.bash_history" nocase
	$s17 = "GET /_sqladm" nocase
	$s18 = "'$IFS/etc/privpasswd;'" nocase
	$s19 = ";cat /tmp/config/usr.ini" nocase
	$s20 = "v0pCr3w" nocase
	$s21 = "eval(base64_decode" nocase
	$s22 = "nob0dyCr3w" nocase
	$s23 = "eval(gzinflate" nocase
	$s24 = "Hacked by" fullword
	$s25 = "%5Bcmd%5D" nocase
	$s26 = "[cmd]" nocase
	$s27 = "union+select" nocase
	$s28 = "UNION%20SELECT" nocase
	$s29 = "(str_rot13" nocase

condition:
	any of ($s*)
}

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
