rule backdoor_apt_pcclient
{
meta:
    author = "@patrickrolsen"
    maltype = "APT.PCCLient"
    filetype = "DLL"
    version = "0.1"
    description = "Detects the dropper: 869fa4dfdbabfabe87d334f85ddda234 AKA dw20.dll/msacm32.drv dropped by 4a85af37de44daf5917f545c6fd03902 (RTF)"
    date = "2012-10"
strings:
    $magic = { 4d 5a } // MZ
    $string1 = "www.micro1.zyns.com"
    $string2 = "Mozilla/4.0 (compatible; MSIE 8.0; Win32)"
    $string3 = "msacm32.drv" wide
    $string4 = "C:\\Windows\\Explorer.exe" wide
    $string5 = "Elevation:Administrator!" wide
    $string6 = "C:\\Users\\cmd\\Desktop\\msacm32\\Release\\msacm32.pdb"
condition:
    $magic at 0 and 4 of ($string*)
}

rule pos_memory_scrapper
{
meta:
    author = "@patrickrolsen"
    maltype = "Point of Sale (POS) Malware Memory Scraper"
    version = "0.1"
    description = "POS Memory Scraper"
    reference = "7f9cdc380eeed16eaab3e48d59f271aa -> http://www.xylibox.com/2013/05/dump-memory-grabber-blackpos.html"
    date = "12/30/2013"
strings:
    $string1 = "kartoxa" nocase
    $string2 = "CC2 region:"
    $string3 = "CC memregion:"
    $string4 = "target pid:"
    $string5 = "scan all processes:"
    $string6 = "<pid> <PATTERN>"
condition:
    all of ($string*)
}

rule FE_PCAPs
{
meta:
    author = "@patrickrolsen"
    maltype = "N/A"
    version = "0.1"
    description = "Find FireEye PCAPs uploaded to Virus Total"
    date = "12/30/2013"
strings:
    $magic = {D4 C3 B2 A1}
    $ip1 = {0A 00 00 ?? C7 10 C7 ??} // "10.0.0.?? -> 199.16.199.??
    $ip2 = {C7 10 C7 ?? 0A 00 00 ??} // "199.16.199.?? -> 10.0.0.??"
condition:
    $magic at 0 and all of ($ip*)
}

// Point of Sale (POS) Malware

rule pos_memory_scrapper2
{
meta:
    author = "@patrickrolsen"
    maltype = "Point of Sale (POS) Malware Memory Scraper"
    version = "0.2"
    description = "POS Memory Scraper"
    reference = "7f9cdc380eeed16eaab3e48d59f271aa http://www.xylibox.com/2013/05/dump-memory-grabber-blackpos.html"
    date = "01/03/2014"
strings:
    $magic = { 4D 5A } // MZ Header
    $string1 = "kartoxa" nocase
    $string2 = "CC2 region:"
    $string3 = "CC memregion:"
    $string4 = "target pid:"
    $string5 = "scan all processes:"
    $string6 = "<pid> <PATTERN>"
    $string7 = "KAPTOXA" nocase
condition:
    ($magic at 0) and all of ($string*)
}
rule pos_malwre_dexter_stardust
{
meta:
    author = "@patrickrolsen"
    maltype = "Dexter Malware - StarDust Variant"
    version = "0.1"
    description = "Table 2 arbornetworks.com/asert/wp-content/uploads/2013/12/Dexter-and-Project-Hook-Break-the-Bank.pdf"
    reference = "16b596de4c0e4d2acdfdd6632c80c070, 2afaa709ef5260184cbda8b521b076e1, and e3dd1dc82ddcfaf410372ae7e6b2f658"
    date = "12/30/2013"
strings:
    $magic = { 4D 5A } // MZ Header
    $string1 = "ceh_3\\.\\ceh_4\\..\\ceh_6"
    $string2 = "Yatoed3fe3rex23030am39497403"
    $string3 = "Poo7lo276670173quai16568unto1828Oleo9eds96006nosysump7hove19"
    $string4 = "CommonFile.exe"
condition:
    ($magic at 0) and all of ($string*)
}
    
rule pos_malware_project_hook
{
meta:
    author = "@patrickrolsen"
    maltype = "Project Hook"
    version = "0.1"
    description = "Table 1 arbornetworks.com/asert/wp-content/uploads/2013/12/Dexter-and-Project-Hook-Break-the-Bank.pdf"
    reference = "759154d20849a25315c4970fe37eac59"
    date = "12/30/2013"
strings:
    $magic = { 4D 5A } // MZ Header
    $string1 = "CallImage.exe"
    $string2 = "BurpSwim"
    $string3 = "Work\\Project\\Load"
    $string4 = "WortHisnal"
    
condition:
    ($magic at 0) and all of ($string*)
}

rule pdb_strings_Rescator
{
meta:
    author = "@patrickrolsen"
    maltype = "N/A Threat Intel..."
    version = "0.2"
    description = "Rescator PDB strings within binaries"
    date = "01/03/2014"
strings:
    $magic = { 4D 5A } // MZ Header
    $pdb1 = "\\Projects\\Rescator" nocase
condition:
    ($magic at 0) and $pdb1
}

rule rtf_Kaba_jDoe
{
meta:
    author = "@patrickrolsen"
    maltype = "APT.Kaba"
    filetype = "RTF"
    version = "0.1"
    description = "fe439af268cd3de3a99c21ea40cf493f, d0e0e68a88dce443b24453cc951cf55f, b563af92f144dea7327c9597d9de574e, and def0c9a4c732c3a1e8910db3f9451620"
    date = "2013-12-10"
strings:
    $magic1 = { 7b 5c 72 74 30 31 } // {\rt01
    $magic2 = { 7b 5c 72 74 66 31 } // {\rtf1
    $magic3 = { 7b 5c 72 74 78 61 33 } // {\rtxa3
    $author1 = { 4A 6F 68 6E 20 44 6F 65 } // "John Doe"
    $author2 = { 61 75 74 68 6f 72 20 53 74 6f 6e 65 } // "author Stone"
    $string1 = { 44 30 [16] 43 46 [23] 31 31 45 }
condition:
    ($magic1 or $magic2 or $magic3 at 0) and all of ($author*) and $string1
} 

rule rtf_yahoo_ken
{
meta:
    author = "@patrickrolsen"
    maltype = "Yahoo Ken"
    filetype = "RTF"
    version = "0.1"
    description = "Test rule"
    date = "2013-12-14"
strings:
    $magic1 = { 7b 5c 72 74 30 31 } // {\rt01
    $magic2 = { 7b 5c 72 74 66 31 } // {\rtf1
    $magic3 = { 7b 5c 72 74 78 61 33 } // {\rtxa3
    $author1 = { 79 61 68 6f 6f 20 6b 65 63 } // "yahoo ken"
condition:
    ($magic1 or $magic2 or $magic3 at 0) and $author1
} 

rule Backdoor_APT_Mongall
{
meta:
    author = "@patrickrolsen"
    maltype = "Backdoor.APT.Mongall"
    version = "0.1"
    reference = "fd69a799e21ccb308531ce6056944842" 
    date = "01/04/2014"
strings:
    $author  = "author user"
    $title   = "title Vjkygdjdtyuj" nocase
    $comp    = "company ooo"
    $cretime = "creatim\\yr2012\\mo4\\dy19\\hr15\\min10"
    $passwd  = "password 00000000"
condition:
        all of them
}

rule tran_duy_linh
{
meta:
    author = "@patrickrolsen"
    maltype = "Misc."
    version = "0.1"
    reference = "8fa804105b1e514e1998e543cd2ca4ea, 872876cfc9c1535cd2a5977568716ae1, etc." 
    date = "2013-12-12"
strings:
    $magic = {D0 CF 11 E0} //DOCFILE0
    $string1 = "Tran Duy Linh" fullword
    $string2 = "DLC Corporation" fullword
condition:
    $magic at 0 and all of ($string*)
}

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
    date = ""12/29/2013""
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

