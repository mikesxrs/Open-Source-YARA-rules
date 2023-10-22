rule php_exploit_GIF
{
meta:
	author = "@patrickrolsen"
	maltype = "GIF Exploits"
	version = "0.1"
	reference = "code.google.com/p/caffsec-malware-analysis"
	date = "2013-12-14"
strings:
	$magic = {47 49 46 38 ?? 61} // GIF8<version>a
	$string1 = "; // md5 Login" nocase
	$string2 = "; // md5 Password" nocase
	$string3 = "shell_exec"
	$string4 = "(base64_decode"
	$string5 = "<?php"
	$string6 = "(str_rot13"
	$string7 = {3c 3f 70 68 70} // <?php
condition:
	($magic at 0) and any of ($string*)
}

rule html_exploit_GIF
{
meta:
	author = "@patrickrolsen"
	maltype = "Web Shells"
	version = "0.1"
	reference = "code.google.com/p/caffsec-malware-analysis"
	date = "2013-12-14"
strings:
	$magic = {47 49 46 38 ?? 61} // GIF8<version>a
	$string1 = {3c 68 74 6d 6c 3e} // <html>
	$string2 = {3c 48 54 4d 4c 3e} // <HTML>
condition:
	($magic at 0) and (any of ($string*))
}

rule web_shell_crews
{
meta:
	author = "@patrickrolsen"
	maltype = "Web Shell Crews"
	version = "0.4"
	reference = "http://www.exploit-db.com/exploits/24905/"
	date = "12/29/2013"
strings:
	$mz = { 4d 5a } // MZ
    
	$string1 = "v0pCr3w"
	$string2 = "BENJOLSHELL"
	$string3 = "EgY_SpIdEr"
	$string4 = "<title>HcJ"
	$string5 = "0wn3d"
	$string6 = "OnLy FoR QbH"
	$string7 = "wSiLm"
	$string8 = "b374k r3c0d3d"
	$string9 = "x'1n73ct|d"
	$string10 = "## CREATED BY KATE ##"
	$string11 = "Ikram Ali"
	$string12 = "FeeLCoMz"
	$string13 = "s3n4t00r"
	$string14 = "FaTaLisTiCz_Fx"
	$string15 = "feelscanz.pl"
	$string16 = "##[ KONFIGURASI"
	$string17 = "Created by Kiss_Me"
	$string18 = "Casper_Cell"
	$string19 = "# [ CREWET ] #"
    	$string20 = "BY MACKER"
    	$string21 = "FraNGky"
    	$string22 = "1dt.w0lf"
    	$string23 = "Modification By iFX" nocase
condition:
	not $mz at 0 and any of ($string*)
}

rule misc_php_exploits
{
meta:
	author = "@patrickrolsen"
	version = "0.4"
	data = "12/29/2013"
	reference = "Virus Total Downloading PHP files and reviewing them..."
strings:
	$mz = { 4d 5a } // MZ
	$php = "<?php"
	$string1 = "eval(gzinflate(str_rot13(base64_decode("
	$string2 = "eval(base64_decode("
	$string3 = "eval(gzinflate(base64_decode("
	$string4 = "cmd.exe /c"
	$string5 = "eva1"
	$string6 = "urldecode(stripslashes("
	$string7 = "preg_replace(\"/.*/e\",\"\\x"
	$string8 = "<?php echo \"<script>"
	$string9 = "'o'.'w'.'s'" // 'Wi'.'nd'.'o'.'w'.'s'
	$string10 = "preg_replace(\"/.*/\".'e',chr"
	$string11 = "exp1ode"
	$string12 = "cmdexec(\"killall ping;"
	$string13 = "r57shell.php"
condition:
	not $mz at 0 and $php and any of ($string*)
}

rule zend_framework
{
meta:
	author = "@patrickrolsen"
	maltype = "Zend Framework"
	version = "0.3"
	date = "12/29/2013"
strings:
	$mz = { 4d 5a } // MZ
	$php = "<?php"
	$string = "$zend_framework" nocase
condition:
	not $mz at 0 and $php and $string
}

rule jpg_web_shell
{
meta:
	author = "@patrickrolsen"
	version = "0.1"
	data = "12/19/2013"
	reference = "http://www.securelist.com/en/blog/208214192/Malware_in_metadata"
strings:
	$magic = { ff d8 ff e? } // e0, e1, e8
	$string1 = "<script src"
	$string2 = "/.*/e"
	$string3 = "base64_decode"
condition:
	($magic at 0) and 1 of ($string*)
}  
