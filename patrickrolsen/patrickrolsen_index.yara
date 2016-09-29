import "pe"

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

rule _Armadillo_v1xx__v2xx
{
meta:
	description = "Armadillo v1.xx - v2.xx"
strings:
	$0 = {55 8B EC 53 8B 5D 08 56 8B 75 0C 57 8B 7D 10 85 F6}
condition:
	$0 at (pe.entry_point)
}

rule bcp_sql_tool
{
meta:
	author = "@patrickrolsen"
	reference = "iSIGHTPartners_ThreatScape_AA_KAPTOXA PDF - 3f00dd56b1dc9d9910a554023e868dac"
	filetype = "EXE"
	version = "0.1"
	date = "1/30/2014"
strings:
	$s1 = "BCP" nocase
	$s2 = "SQLState = %s"
	$s3 = "Warning = %s"
	$s5 = ";database="
	$s6 = "FIRE_TRIGGERS"

condition:
	uint16(0) == 0x5A4D and (all of ($s*))
}


rule beep_remote_shell
{
	meta:
	author = "@patrickrolsen"
	reference = "0625b5b010a1acb92f02338b8e61bb34"
	filetype = "EXE"
	version = "0.1"
	date = "1/29/2014"
strings:
	$mz = { 4d 5a }
	$s1 = "%s\\admin$\\system32\\%s"
	$s2 = "BeepService"
	$s3 = "In ControlService"
	$s4 = "In OpenScManager"
	$s5 = "In CreateService"
	$s6 = "Service is RUNNING"
	$s7 = "Service is not running"
	$s8 = "In DeleteService"
	$s9 = "Remove the service OK"
condition:
	($mz at 0) and (all of ($s*))
}

rule blat_email_301
{
meta:
	author = "@patrickrolsen"
strings:
	$s1 = {33 00 2E 00 30 00 2E 00 31} // 301 uni
	$s2 = "Mar  7 2012"
condition:
	uint16(0) == 0x5A4D and (all of ($s*))
}


rule blazingtools
{
meta:
	author = "@patrickrolsen"
	reference = "Blazing Tools - http://www.blazingtools.com (Keyloggers)"
strings:
	$s1 = "blazingtools.com"
	$s2 = "Keystrokes" wide
	$s3 = "Screenshots" wide
condition:
	uint16(0) == 0x5A4D and all of ($s*)
}

rule cmd_shell
{
meta:
	author = "@patrickrolsen"
	reference = "Windows CMD Shell"
	filetype = "EXE"
	version = "0.1"
	date = "1/30/2014"
strings:
	$s1 = "cmd.pdb"
	$s2 = "CMD Internal Error %s"
condition:
	uint16(0) == 0x5A4D and (all of ($s*)) and filesize <= 380KB
}

rule html_CVE_2013_1347
{
meta:
	author = "@patrickrolsen"
	reference = "http://blogs.cisco.com/security/watering-hole-attacks-target-energy-sector"
	hashes = "00ca490898740f9b6246e300ef0ee86f and dc681f380698b2e6dca7c49f699799ad"
	date = "02/01/2014"
strings:
	$html = "html" wide ascii
	$s1 = "DOropRAM" wide ascii
	$s2 = "\\u9090\\u9090\\u9090\\u9090" wide ascii
	$s3 = "shellcode" wide ascii
	$s4 = "unicorn" wide ascii
	$s5 = "helloWorld()" wide ascii
	$s6 = "ANIMATECOLOR" wide ascii
	$s7 = "UPXIgLvY" wide ascii
condition:
	$html and 3 of ($s*)
}

rule dark_edition
{
meta:
	author = "@patrickrolsen"
	maltype = "EXE"
	version = "0.1"
	reference = "Dark Edition" 
strings:
	$s1 = "[ Dark Edition ]" wide
condition:
    uint16(0) == 0x5A4D and $s1
}

rule dump_tool
{
meta:
	author = "@patrickrolsen"
	reference = "Related to pwdump6 and fgdump tools"
strings:
	$s1 = "lsremora"
	$s2 = "servpw"
	$s3 = "failed: %d"
	$s4 = "fgdump"
	$s5 = "fgexec"
	$s6 = "fgexecpipe"
condition:
	uint16(0) == 0x5A4D and 3 of ($s*)
}

rule GIF_exploit
{
meta:
	author = "@patrickrolsen"
	maltype = "GIF Exploits"
	version = "0.1"
	reference = "code.google.com/p/caffsec-malware-analysis"
	date = "2013-12-14"
strings:
	$magic = {47 49 46 38 ?? 61} // GIF8<version>a
	$s1 = "; // md5 Login" nocase
	$s2 = "; // md5 Password" nocase
	$s3 = "shell_exec"
	$s4 = "(base64_decode"
	$s5 = "<?php"
	$s6 = "(str_rot13"
	$s7 = ".exe"
	$s8 = ".dll"
	$s9 = "eval($_"
condition:
	($magic at 0) and any of ($s*)
}

rule gsec_generic
{
meta:
	author = "@patrickrolsen"
	reference = "GSec Dump"
	filetype = "EXE"
	version = "0.1"
	date = "1/29/2014"
strings:
	$s1 = "gsecdump"
	$s2 = "usage: gsecdump"
	$s3 = "dump hashes from SAM//AD"
	$s4 = "dump lsa secrets"
	$s5 = "dump_"
	$s6 = "dump all secrets"
condition:
	uint16(0) == 0x5A4D and (all of ($s*))
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
	$s1 = {3c 68 74 6d 6c 3e} // <html>
	$s2 = {3c 48 54 4d 4c 3e} // <HTML>
condition:
	($magic at 0) and (any of ($s*))
}

/*
rule jpg_web_shell
{
meta:
	author = "@patrickrolsen"
	version = "0.1"
	data = "12/19/2013"
	reference = "http://www.securelist.com/en/blog/208214192/Malware_in_metadata"
strings:
	$magic = { ff d8 ff e? } // e0, e1, e8
	$s1 = "<script src"
	$s2 = "/.*//*e"
	$s3 = "base64_decode"
condition:
	($magic at 0) and 1 of ($s*)
}  
*/


rule malicious_LNK_files
{
strings:
	$magic = {4C 00 00 00 01 14 02 00} // L.......
	$s1 = "\\RECYCLER\\" wide
	$s2 = "%temp%" wide
	$s3 = "%systemroot%\\system32\\cmd.exe" wide
	//$s4 = "./start" wide
	$s5 = "svchost.exe" wide
	$s6 = "lsass.exe" wide
	$s7 = "csrss.exe" wide
	$s8 = "winlogon.exe" wide
	//$s9 = "%cd%" wide
	$s10 = "%appdata%" wide
	$s11 = "%programdata%" wide
	$s12 = "%localappdata%" wide
	$s13 = ".cpl" wide
condition:
	($magic at 0) and any of ($s*)
}

rule luxnet
{
meta:
	author = "@patrickrolsen"
	maltype = "EXE"
	version = "0.1"
	reference = "Luxnet RAT - http://leak.sx/thread-254973" 
strings:
	$s1 = "XilluX" wide nocase
	$s2 = "Xanity" wide nocase
	$s3 = "PHP RAT Client" wide
condition:
    uint16(0) == 0x5A4D and 1 of ($s*)
}

rule misc_iocs
{
meta:
	author = "@patrickrolsen"
	maltype = "Misc."
	version = "0.1"
	reference = "N/A" 
strings:
	$doc = {D0 CF 11 E0} //DOCFILE0
	$s1 = "dw20.exe"
	$s2 = "cmd /"
condition:
    ($doc at 0) and (1 of ($s*))
}

rule misc_php_exploits
{
meta:
	author = "@patrickrolsen"
	version = "0.5"
	data = "08/19/2014"
	reference = "Virus Total Downloading PHP files and reviewing them..."
strings:
	$php = "<?php" nocase
	$s1 = "eval(gzinflate(str_rot13(base64_decode("
	$s2 = "eval(base64_decode("
	$s3 = "eval(gzinflate(base64_decode("
	$s4 = "cmd.exe /c"
	$s5 = "eva1"
	$s6 = "urldecode(stripslashes("
	$s7 = "preg_replace(\"/.*/e\",\"\\x"
	$s8 = "<?php echo \"<script>"
	$s9 = "'o'.'w'.'s'" // 'Wi'.'nd'.'o'.'w'.'s'
	$s10 = "preg_replace(\"/.*/\".'e',chr"
	$s11 = "exp1ode"
	$s12 = "cmdexec(\"killall ping;"
	$s13 = "ms-mx.ru"
	$s14 = "N3tsh_"
	$s15 = "eval(\"?>\".gzinflate(base64_decode("
	$s16 = "Your MySQL database has been backed up"
	$s17 = "Idea Conceived By"
	$s18 = "ncftpput -u $ftp_user_name -p $ftp_user_pass"
	$s19 = "eval(gzinflate(base64_decode("
	$s20 = "DTool Pro"
condition:
	not uint16(0) == 0x5A4D and $php and any of ($s*)
}

rule misc_shells
{
meta:
	author = "@patrickrolsen"
	version = "0.3"
	data = "08/19/2014"
strings:
	$s1 = "second stage dropper"
	$s2 = "SO dumped "
	$s3 = "killall -9 "
	$s4 = "1.sh"
	$s5 = "faim.php"
	$s6 = "file_get_contents("
	$s7 = "$auth_pass ="
	$s8 = "eval($" // Possible FPs
	$s9 = "Find *config*.php"
	$s10 = "Show running services"
	$s11 = "Show computers"
	$s12 = "Show active connections"
	$s13 = "ARP Table"
	$s14 = "Last Directory"
	$s15 = ".htpasswd files"
	$s16 = "suid files"
	$s17 = "writable folders"
	$s18 = "config* files"
	$s19 = "show opened ports"
	$s20 = ".pwd files"
	$s21 = "locate config."
	$s22 = "history files"
	$s23 = "<?php @eval($_POST['cmd']);?>"
	$s24 = "securityprobe.net"
	$s25 = "ccteam.ru"
	$s26 = "c99sh_sources"
	$s27 = "c99mad"
	$s28 = "31373"
	$s29 = "c99_sess_put"
	$s30 = "(\"fs_move_"
	$s31 = "c99sh_bindport_"
	$s32 = "mysql_dump"
	$s33 = "Change this to your password"
	$s34 = "ps -aux"
	$s35 = "p4ssw0rD"
	$s36 = "Ajax Command Shell by"
	$s37 = "greetings to everyone in rootshell"
	$s38 = "We now update $work_dir to avoid things like"
	$s39 = "ls looks much better with"
	$s40 = "I Always Love Sha"
	$s41 = "fileperm=substr(base_convert(fileperms"
	$s42 = "W A R N I N G: Private Server"
	$s43 = "for power security"
	$s44 = "[kalabanga]"
	$s45 = "GO.cgi"
	$s46 = "eval(gzuncompress(base64_decode("
	$s47 = "ls -lah"
	$s48 = "uname -a"
	$s49 = "imageshack.us"
	$s50 = "For Server Hacking"
	$s51 = "Private Exploit"
	$s52 = "chunk_split(base64_encode("
	$s53 = "ending mail to $to......."
	$s54 = "Mysql interface"
	$s55 = "MySQL Database Backup"
	$s56 = "mysql_tool.php?act=logout"
	$s57 = "Directory Lister"
	$s58 = "username and pass here"
	$s59 = "echo base64_decode($"
	$s60 = "get_current_user("
	$s61 = "hey,specify directory!"
	$s62 = "execute command:"
	$s63 = "FILE UPLOADED TO $"
	$s64 = "This server has been infected by"
	$s65 = "Safe_Mode Bypass"
	$s66 = "Safe Mode Shell"
	$s67 = "CMD ExeCute"
	$s68 = "/etc/passwd"
condition:
	not uint16(0) == 0x5A4D and any of ($s*)
}

rule monitor_tool_pos
{
meta:
	author = "@patrickrolsen"
	reference = "POS malware - Monitoring Tool??"
strings:
	$s1 = "RCPT TO"
	$s2 = "MAIL FROM"
	$s3 = "AUTH LOGIN"
	$s4 = "Reply-To"
	$s5 = "X-Mailer"
	$s6 = "crypto"
	$s7 = "test335.txt" wide
	$s8 = "/c del"
condition:
	uint16(0) == 0x5A4D and 7 of ($s*)
}

rule mpress_2_xx_net : Packer
{
meta:
	author="Kevin Falcoz"
	date_create="24/03/2013"
	description="MPRESS v2.XX .NET"
strings:
	$signature1={21 46 00 69 00 6C 00 65 00 20 00 69 00 73 00 20 00 69 00 6E 00 76 00 61 00 6C 00 69 00 64 00 2E 00 00 0D 4D 00 50 00 52 00 45 00 53 00 53 00 00 00 00 00 2D 2D 93 6B 35 04 2E 43 85 EF}
condition:
	$signature1
    }

rule mpress_2_xx_x64 : Packer
{
meta:
	author="Kevin Falcoz"
	date_create="19/03/2013"
	last_edit="24/03/2013"
	description="MPRESS v2.XX x64  - no .NET"

strings:
	$signature1={57 56 53 51 52 41 50 48 8D 05 DE 0A 00 00 48 8B 30 48 03 F0 48 2B C0 48 8B FE 66 AD C1 E0 0C 48 8B C8 50 AD 2B C8 48 03 F1 8B C8 57 44 8B C1 FF C9 8A 44 39 06 88 04 31} 
condition:
	$signature1 at (pe.entry_point)
}

rule mpress_2_xx_x86 : Packer
{
meta:
	author="Kevin Falcoz"
	date_create="19/03/2013"
	last_edit="24/03/2013"
	description="MPRESS v2.XX x86  - no .NET"

strings:
	$signature1={60 E8 00 00 00 00 58 05 5A 0B 00 00 8B 30 03 F0 2B C0 8B FE 66 AD C1 E0 0C 8B C8 50 AD 2B C8 03 F1 8B C8 57 51 49 8A 44 39 06 88 04 31 75 F6 2B C0 AC 8B C8 80 E1 F0 24} 
condition:
	$signature1 at (pe.entry_point)
}

rule nbtscan
{
meta:
	author = "@patrickrolsen"
	reference = "nbtscan"
	filetype = "EXE"
	version = "0.1"
	date = "1/30/2014"
strings:
	$s1 = "nbtscan" nocase
	$s2 = "subnet /%d"
	$s3 = "invalid target"
	$s4 = "usage: %s"
condition:
	uint16(0) == 0x5A4D and (all of ($s*))
}

rule osql_tool
{
meta:
	author = "@patrickrolsen"
	reference = "O/I SQL - SQL query tool"
	filetype = "EXE"
	version = "0.1"
	date = "1/30/2014"
strings:
	$s1 = "osql\\src"
	$s2 = "OSQLUSER"
	$s3 = "OSQLPASSWORD"
	$s4 = "OSQLSERVER"
condition:
	uint16(0) == 0x5A4D and (all of ($s*))
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

rule port_forward_tool
{
meta:
	author = "@patrickrolsen"
	reference = "Port Forwarding Tool"
	filetype = "EXE"
	version = "0.1"
	date = "1/30/2014"
strings:
	$s1 = "%d.%d.%d.%d"
	$s2 = "%i.%i.%i.%i on port %i"
	$s3 = "connect to %s:%i"
	$s4 = "%s:%i established"
	$s5 = "%s:%i closed"
condition:
	uint16(0) == 0x5A4D and (all of ($s*))
}


// Point of Sale (POS) Malware and Tools used during POS compromises

rule blackpos_v2
{
meta:
	author = "@patrickrolsen"
	version = "0.1"
	reference = "http://blog.nuix.com/2014/09/08/blackpos-v2-new-variant-or-different-family"
strings:
	$s1 = "Usage: -[start|stop|install|uninstall"
	$s2 = "\\SYSTEM32\\sc.exe config LanmanWorkstation"
	$s3 = "t.bat"
	$s4 = "mcfmisvc"
condition:
	uint16(0) == 0x5A4D and all of ($s*)
}


rule misc_pos
{
meta:
	author = "@patrickrolsen"
	reference = "POS Malware"
strings:
	$s1 = "KAPTOXA"
	$s2 = "cmd /c net start %s"
	$s3 = "pid:"
	$s4 = "%ADD%"
	$s5 = "COMSPEC"
	$s6 = "KARTOXA"
condition:
	uint16(0) == 0x5A4D and 3 of ($s*)
}

rule unknown
{
meta:
	author = "@patrickrolsen"
	reference = "Unknown POS"
strings:
	$s1 = "a.exe" wide
	$s2 = "Can anyone test" wide
	$s3 = "I m in computer class now" wide
condition:
	uint16(0) == 0x5A4D and 3 of ($s*)
}

rule regex_pos
{
meta:
	author = "@patrickrolsen"
	reference = "POS malware - Regex"
strings:
	$n1 = "REGEXEND" nocase
	$n2 = "RegExpr" nocase
	$n3 = "regex"
	$s4 = "[1-5][0-9]{14}=(?!1201|1202|1203|1204|11|10|09|08|07|06|05|04|03|02)[0-9]{5}[0-9]*"
	$s5 = "[47][0-9]{13}=(?!1201|1202|1203|1204|11|10|09|08|07|06|05|04|03|02)[0-9]{5}[0-9]*"
	$s6 = "(?:0[0-5]|[68][0-9])[0-9]{11}=(?!1201|1202|1203|1204|11|10|09|08|07|06|05|04|03|02)[0-9]{5}[0-9]*"
	$s7 = "(?:011|5[0-9]{2})[0-9]{12}=(?!1201|1202|1203|1204|11|10|09|08|07|06|05|04|03|02)[0-9]{5}[0-9]*"
	$s8 = "(?:2131|1800|35\\d{3})\\d{11}=(?!1201|1202|1203|1204|11|10|09|08|07|06|05|04|03|02)[0-9]{5}[0-9]*"
	$s9 = "([0-9]{15,16}[D=](0[7-9]|1[0-5])((0[1-9])|(1[0-2]))[0-9]{8,30})"
	$s10 = "((b|B)[0-9]{13,19}\\^[A-Za-z\\s]{0,30}\\/[A-Za-z\\s]{0,30}\\^(0[7-9]|1[0-5])((0[1-9])|(1[0-2]))[0-9\\s]{3,50}[0-9]{1})"
	$s11 = "[0-9]*\\^[a-zA-Z]*/[a-zA-Z ]*\\^[0-9]*"
	$s12 = "\\d{15,19}=\\d{13,}"
	$s13 = "\\;?[3-9]{1}[0-9]{12,19}[D=\\u0061][0-9]{10,30}\\??"
	$s14 = "[0-9]{12}(?:[0-9]{3})?=(?!1201|1202|1203|1204|11|10|09|08|07|06|05|04|03|02)[0-9]{5}[0-9]*"
condition:
	uint16(0) == 0x5A4D and 1 of ($n*) and 1 of ($s*)
}

rule regexpr_pos
{
meta:
	author = "@patrickrolsen"
	reference = "POS malware - RegExpr"
strings:
	$s1 = "RegExpr" nocase
	$s2 = "Data.txt"
	$s3 = "Track1"
	$s4 = "Track2"
condition:
	uint16(0) == 0x5A4D and 3 of ($s*)
}

rule reg_pos
{
meta:
	author = "@patrickrolsen"
	reference = "POS malware - RegExpr"
strings:
	$s1 = "T1_FOUND: %s"
	$s2 = "id=%s&log=%s"
	$s3 = "\\d{15,19}=\\d{13,}"
condition:
	uint16(0) == 0x5A4D and 2 of ($s*)
}

rule sets_pos
{
meta:
	author = "@patrickrolsen"
	reference = "POS malware - Sets"
strings:
	$s1 = "GET /sets.txt"
condition:
	uint16(0) == 0x5A4D and $s1
}


rule pstgdump
{
meta:
	author = "@patrickrolsen"
	reference = "pstgdump"
strings:
	$s1 = "fgdump\\pstgdump"
	$s2 = "pstgdump"
	$s3 = "Outlook"
condition:
	uint16(0) == 0x5A4D and all of ($s*)
}

rule keyfinder_tool
{
meta:
	author = "@patrickrolsen"
	reference = "Magical Jelly Bean KeyFinder"
strings:
	$s1 = "chgxp.vbs"
	$s2 = "officekey.exe"
	$s3 = "findkey.exe"
	$s4 = "xpkey.exe"
condition:
	uint16(0) == 0x5A4D and 2 of ($s*)
}

rule memdump_diablo
{
meta:
	author = "@patrickrolsen"
	reference = "Process Memory Dumper - DiabloHorn"
strings:
	$s1 = "DiabloHorn"
	$s2 = "Process Memory Dumper"
	$s3 = "pid-%s.dmp"
	$s4 = "Pid %d in not acessible" // SIC
	$s5 = "memdump.exe"
	$s6 = "%s-%d.dmp"
condition:
	uint16(0) == 0x5A4D and 3 of ($s*)
}


rule sysocmgr
{
meta:
	author = "@patrickrolsen"
	reference = "System stand-alone Optional Component Manager - http://support.microsoft.com/kb/222444"
strings:
	$s1 = "SYSOCMGR.EXE" wide
	$s2 = "System stand-alone Optional Component Manager" wide
condition:
	uint16(0) == 0x5A4D and all of ($s*)
}


rule lacy_keylogger
{
meta:
	author = "@patrickrolsen"
	reference = "Appears to be a form of keylogger."
strings:
	$s1 = "Lacy.exe" wide
	$s2 = "Bldg Chive Duel Rip Query" wide
condition:
	uint16(0) == 0x5A4D and all of ($s*)
}

rule searchinject
{
meta:
	author = "@patrickrolsen"
	reference = "Usage: SearchInject <PID1>[PID2][PID3] - It loads Searcher.dll (appears to be hard coded)"
strings:
	$s1 = "SearchInject"
	$s2 = "inject base:"
	$s3 = "Searcher.dll" nocase
condition:
	uint16(0) == 0x5A4D and all of ($s*)
}


rule heistenberg_pos
{
meta:
	author = "@patrickrolsen"
	reference = "POS Malware"
strings:
	$s1 = "KARTOXA"
	$s2 = "dmpz.log"
	$s3 = "/api/process.php?xy="
	$s4 = "User-Agent: PCICompliant" // PCICompliant/3.33
	$s6 = "%s:*:Enabled:%s"
condition:
	uint16(0) == 0x5A4D and 3 of ($s*)
}

rule pos_jack
{
meta:
	author = "@patrickrolsen"
	maltype = "Point of Sale (POS) Malware"
	version = "0.1"
	reference = "http://blog.spiderlabs.com/2014/02/jackpos-the-house-always-wins.html"
	date = "2/22/2014"
strings:
	$pdb1 = "\\ziedpirate.ziedpirate-PC\\"
	$pdb2 = "\\sop\\sop\\"
condition:
	uint16(0) == 0x5A4D and 1 of ($pdb*)
}

rule pos_memory_scrapper_
{
meta:
	author = "@patrickrolsen"
	maltype = "Point of Sale (POS) Malware Memory Scraper"
	version = "0.3"
	description = "POS Memory Scraper"
	date = "01/30/2014"
strings:
	$s1 = "kartoxa" nocase
	$s2 = "CC2 region:"
	$s3 = "CC memregion:"
	$s4 = "target pid:"
	$s5 = "scan all processes:"
	$s6 = "<pid> <PATTERN>"
	$s7 = "KAPTOXA"
	$s8 = "ATTERN"
	$s9 = "\\svhst%p"
condition:
	uint16(0) == 0x5A4D and 3 of ($s*)
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
	$s1 = "ceh_3\\.\\ceh_4\\..\\ceh_6"
	$s2 = "Yatoed3fe3rex23030am39497403"
	$s3 = "Poo7lo276670173quai16568unto1828Oleo9eds96006nosysump7hove19"
	$s4 = "CommonFile.exe"
condition:
	uint16(0) == 0x5A4D and all of ($s*)
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
	$s1 = "CallImage.exe"
	$s2 = "BurpSwim"
	$s3 = "Work\\Project\\Load"
	$s4 = "WortHisnal"
condition:
	uint16(0) == 0x5A4D and all of ($s*)
}

rule pdb_strings_Rescator
{
meta:
	author = "@patrickrolsen"
	maltype = "Target Attack"
	version = "0.3"
	description = "Rescator PDB strings within binaries"
	date = "01/30/2014"
strings:
	$pdb1 = "\\Projects\\Rescator" nocase
condition:
	uint16(0) == 0x5A4D and $pdb1
}

rule pos_uploader
{
meta:
	author = "@patrickrolsen"
	maltype = "Point of Sale (POS) Malware"
    reference = "http://blogs.mcafee.com/mcafee-labs/analyzing-the-target-point-of-sale-malware"
	version = "0.1"
	description = "Testing the base64 encoded file in sys32"
	date = "01/30/2014"
strings:
	$s1 = "cmd /c net start %s"
	$s2 = "ftp -s:%s"
	$s3 = "data_%d_%d_%d_%d_%d.txt"
	$s4 = "\\uploader\\"
condition:
	uint16(0) == 0x5A4D and all of ($s*)
}

rule winxml_dll
{
meta:
	author = "@patrickrolsen"
	maltype = "Point of Sale (POS) Malware"
    reference = "ce0296e2d77ec3bb112e270fc260f274"
	version = "0.1"
	description = "Testing the base64 encoded file in sys32"
	date = "01/30/2014"
strings:
	$s1 = "\\system32\\winxml.dll"
	//$s2 = "cmd /c net start %s"
	//$s3 = "=== pid:"
	//$s4 = "GOTIT"
	//$s5 = ".memdump"
	//$s6 = "POSWDS"
condition:
	uint16(0) == 0x5A4D and (all of ($s*))
}

rule pos_chewbacca
{
meta:
	author = "@patrickrolsen"
	maltype = "Point of Sale (POS) Malware"
    reference = "https://www.securelist.com/en/blog/208214185/ChewBacca_a_new_episode_of_Tor_based_Malware"
    hashes = "21f8b9d9a6fa3a0cd3a3f0644636bf09, 28bc48ac4a92bde15945afc0cee0bd54"
	version = "0.2"
	description = "Testing the base64 encoded file in sys32"
	date = "01/30/2014"
strings:
	$s1 = "tor -f <torrc>"
	$s2 = "tor_"
	$s3 = "umemscan"
	$s4 = "CHEWBAC"
condition:
	uint16(0) == 0x5A4D and (all of ($s*))
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
    $string7 = "KAPTOXA"
condition:
	all of ($string*)
}

rule procdump
{
meta:
	author = "@patrickrolsen"
	reference = "Procdump"
	filetype = "EXE"
	version = "0.1"
	date = "1/30/2014"
strings:
	$s1 = "\\Procdump\\"
	$s2 = "procdump"
	$s3 = "Process"
condition:
	uint16(0) == 0x5A4D and (all of ($s*))
}

rule psexec_generic
{
meta:
	author = "@patrickrolsen"
	reference = "Sysinternals PsExec Generic"
	filetype = "EXE"
	version = "0.2"
	date = "1/30/2014"
strings:
	$s1 = "PsInfSvc"
	$s2 = "%s -install"
	$s3 = "%s -remove"
	$s4 = "psexec" nocase
condition:
	uint16(0) == 0x5A4D and (all of ($s*))
}

rule rtf_multiple
{
meta:
	author = "@patrickrolsen"
	maltype = "Multiple"
	version = "0.1"
	reference = "fd69a799e21ccb308531ce6056944842" 
	date = "01/04/2014"
strings:
	$rtf = { 7b 5c 72 74 ?? ?? } // {\rt01 {\rtf1 {\rtxa
    $string1  = "author user"
	$string2   = "title Vjkygdjdtyuj" nocase
	$string3    = "company ooo"
	$string4  = "password 00000000"
condition:
    ($rtf at 0) and (all of ($string*))
}

rule scanline_mcafee
{
meta:
	author = "@patrickrolsen"
	reference = "http://www.mcafee.com/us/downloads/free-tools/scanline.aspx"
	filetype = "EXE"
	version = "0.1"
	date = "1/30/2014"
strings:
	$s1 = "CPports.txt"
	$s2 = "ICMP Time"
	$s3 = "Foundsto"
	$s4 = "USER"
	$s5 = {55 50 58 ??} // UPX?
condition:
	uint16(0) == 0x5A4D and (all of ($s*))
}

rule seven_zip_cmdversion
{
meta:
	author = "@patrickrolsen"
	reference = "http://www.7-zip.org/download.html"
	filetype = "EXE"
	version = "0.1"
	date = "1/30/2014"
strings:
	$s1 = "7za"
	$s2 = "7-Zip"
	$s3 = "Usage:"
condition:
	uint16(0) == 0x5A4D and (all of ($s*))
}

rule shell_functions
{
meta:
	author = "@patrickrolsen"
	version = "0.1"
	data = "08/19/2014"
	reference = "N/A"
strings:
	$s1 = "function listDatabases()"
	$s2 = "function dropDatabase()"
	$s3 = "mysql_drop_db("
	$s4 = "function listTables()"
	$s5 = "passthru($cmd)"
	$s6 = "function check_file()"
	$s7 = "$id==\"fake-mail\""
	$s8 = "Shell_Exec($cmd)"
	$s9 = "move_uploaded_file("
condition:
	not uint16(0) == 0x5A4D and any of ($s*)
}

rule shell_names
{
meta:
	author = "@patrickrolsen"
	version = "0.3"
	data = "08/19/2014"
	reference = "N/A"
strings:
	$s1 = "faim.php"
	$s2 = "css5.php"
	$s3 = "groanea.php"
	$s4 = "siler.php"
	$s5 = "w.php" fullword
	$s6 = "atom-conf.php"
	$s7 = "405.php"
	$s8 = "pack2.php"
	$s9 = "r57shell.php"
	$s10 = "shell.php" fullword
	$s11 = "dra.php"
	$s12 = "lol.php"
	$s13 = "php-backdoor.php"
	$s14 = "aspxspy.aspx"
	$s15 = "c99.php"
	$s16 = "c99shell.php"
	$s17 = "fx29sh.php"
	$s18 = "azrailphp.php"
	$s19 = "CmdAsp.asp"
	$s20 = "dingen.php"
	$s21 = "entrika.php"
condition:
	not uint16(0) == 0x5A4D and any of ($s*)
}

rule sneakernet_trojan
{
meta:
	author = "@patrickrolsen"
	maltype = "Sneakernet Trojan"
	version = "0.1"
	reference = "http://www.fidelissecurity.com/webfm_send/375" 
	date = "01/30/2014"
strings:
    $s1 = "Mtx_Sp_On_PC_1_2_8"
    $s2 = "%s /c del %s"
    $s3 = "RECYCLED"
condition:
    uint16(0) == 0x5A4D and (all of ($s*))
}

rule tran_duy_linh
{
meta:
	author = "@patrickrolsen"
	maltype = "Misc."
	version = "0.2"
	reference = "8fa804105b1e514e1998e543cd2ca4ea, 872876cfc9c1535cd2a5977568716ae1, etc." 
	date = "01/03/2014"
strings:
	$doc = {D0 CF 11 E0} //DOCFILE0
	$string1 = "Tran Duy Linh" fullword
	$string2 = "DLC Corporation" fullword
condition:
    ($doc at 0) and (all of ($string*))
}

rule unknown_creds_dump
{
meta:
	author = "@patrickrolsen"
	reference = "Misc. Creds Dump"
	filetype = "EXE"
	version = "0.1"
	date = "1/30/2014"
strings:
	$s1 = "OpenProcessToken:%d"
	$s2 = "LookupPrivilegeValue:%d"
	$s3 = "AdjustTokenPrivilege:%d"
	$s4 = "\\GetPassword\\"
condition:
	uint16(0) == 0x5A4D and (all of ($s*))
}


rule _UPX_290_LZMA
{
meta:
	description = "UPX 2.90 [LZMA] -> Markus Oberhumer, Laszlo Molnar & John Reiser"
strings:
	$0 = {60 BE ?? ?? ?? ?? 8D BE ?? ?? ?? ?? 57 83 CD FF EB 10 90 90 90 90 90 90 8A 06 46 88 07 47 01 DB 75 07 8B 1E 83 EE FC 11 DB 72 ED B8 01 00 00 00 01 DB 75 07 8B 1E 83 EE FC 11 DB 11 C0 01 DB}
	$1 = {60 BE ?? ?? ?? ?? 8D BE ?? ?? ?? ?? 57 83 CD FF 89 E5 8D 9C 24 ?? ?? ?? ?? 31 C0 50 39 DC 75 FB 46 46 53 68 ?? ?? ?? ?? 57 83 C3 04 53 68 ?? ?? ?? ?? 56 83 C3 04 53 50 C7 03 ?? ?? ?? ?? 90 90}
condition:
	$0 at (pe.entry_point) or $1 at (pe.entry_point)
}

rule _UPX_Protector_v10x_2
{
meta:
	description = "UPX Protector v1.0x (2)"
strings:
	$0 = {EB ?? ?? ?? ?? ?? 8A 06 46 88 07 47 01 DB 75 07 8B 1E 83 EE FC 11 DB}
condition:
	$0
}

rule _UPX_V200V290
{
meta:
	description = "UPX V2.00-V2.90 -> Markus Oberhumer & Laszlo Molnar & John Reiser"
strings:
	$0 = {FF D5 8D 87 ?? ?? ?? ?? 80 20 ?? 80 60 ?? ?? 58 50 54 50 53 57 FF D5 58 61 8D 44 24 ?? 6A 00 39 C4 75 FA 83 EC 80 E9}
condition:
	$0
}

rule _UPX_v0896
{
meta:
	description = "UPX v0.89.6 - v1.02 / v1.05 - v1.22 DLL"
strings:
	$0 = {80 7C 24 08 01 0F 85 ?? ?? ?? 00 60 BE ?? ?? ?? ?? 8D BE ?? ?? ?? ?? 57 83 CD FF}
condition:
	$0 at (pe.entry_point)
}

rule web_log_review
{
meta:
	author = "@patrickrolsen"
	version = "0.1"
	reference = "http://blog.shadowserver.org/2013/05/06/breaking-the-kill-chain-with-log-analysis/"
	date = "2013-12-14"
strings:
	$s =   "GET /.htaccess"
	$s0 =  "GET /db/main.php"
	$s3 =  "GET /dbadmin/main.php"
	$s4 =  "GET /phpinfo.php"
	$s5 =  "GET /password"
	$s6 =  "GET /passwd"
	$s7 =  "GET /phpmyadmin2"
	$s10 = "GET /response.write"
	$s11 = "GET /&dir"
	$s13 = "GET /.htpasswd"
	$s14 = "GET /htaccess.bak"
	$s15 = "GET /htaccess.txt"
	$s16 = "GET /.bash_history"
	$s17 = "GET /_sqladm"
	$s18 = "'$IFS/etc/privpasswd;'"
	$s19 = ";cat /tmp/config/usr.ini"
	$s21 = "eval(base64_decode"
	$s23 = "eval(gzinflate"
	$s25 = "%5Bcmd%5D"
	$s26 = "[cmd]"
	$s27 = "union+select" nocase
	$s28 = "UNION%20SELECT" nocase
	$s29 = "(str_rot13"
	$s30 = "GET /private.key"
	$s31 = "GET /database.inc"
	$s32 = "GET /webstats.html"
	$s33 = "GET /schema.sql"
	$s34 = "GET /customers"
	$s35 = "GET /images/passwords.mdb"
	$s36 = "GET /web-console"
	$s37 = "GET /phpmyadmin/main.php"
	$s38 = "GET /mysql/main.php"
	$s39 = "GET /memberlist"
	$s40 = "GET /logs"
	$s41 = "GET /%26cat%20%2fetc%2fpasswd"
	$s42 = "GET /New%20folder%20(2)"
	$s43 = "GET /response.write(9674459*9948960)"
	$s44 = "GET /index.php?"
	$s45 = "concat(user_login"
	$s46 = "),user_pass)"
	$s47 = "sqlmap"
condition:
	any of ($s*)
}

rule web_shell_crews
{
meta:
	author = "@patrickrolsen"
	maltype = "Web Shell Crews"
	version = "0.6"
	reference = "http://www.exploit-db.com/exploits/24905/"
	date = "08/19/2014"
strings:
	$s1 = "v0pCr3w"
	$s2 = "BENJOLSHELL"
	$s3 = "EgY_SpIdEr"
	$s4 = "<title>HcJ"
	$s5 = "0wn3d"
	$s6 = "OnLy FoR QbH"
	$s7 = "wSiLm"
	$s8 = "b374k r3c0d3d"
	$s9 = "x'1n73ct|d"
	$s10 = "## CREATED BY KATE ##"
	$s11 = "Ikram Ali"
	$s12 = "FeeLCoMz"
	$s13 = "s3n4t00r"
	$s14 = "FaTaLisTiCz_Fx"
	$s15 = "feelscanz.pl"
	$s16 = "##[ KONFIGURASI"
	$s17 = "Created by Kiss_Me"
	$s18 = "Casper_Cell"
	$s19 = "# [ CREWET ] #"
	$s20 = "BY MACKER"
	$s21 = "FraNGky"
	$s22 = "1dt.w0lf"
	$s23 = "Modification By iFX"
	$s24 = "Dumped by C99madShell.SQL"
	$s25 = "Hacked By Alaa"
	$s26 = "XXx_Death_xXX"
	$s27 = "zehir3"
	$s28 = "zehirhacker"
	$s29 = "Shell Tcrew"
	$s30 = "w4ck1ng"
	$s31 = "TriCkz"
	$s32 = "TambukCrew"
	$s33 = "Dumped by c100.SQL"
	$s34 = "Hacker By Task QQ"
	$s35 = "JyHackTeam"
	$s36 = "byMesaj"
	$s37 = "by STHx"
	$s38 = "hacker!@#"
	$s39 = "Fucked by 7sign"
	$s40 = "Hacked By:NsQk"
	$s41 = "Ch1na HLD Secur1ty Team"
	$s42 = "hackxsy.net"
	$s43 = "[Black Tie]"
	$s44 = "[ Black Tie ]"
	$s45 = "X4ck By Death"
	$s46 = "Recoded bY 0x14113"
	$s47 = "0x14113_Server Shell"
	$s48 = "BY 0x14113"
	$s49 = "[ 0x14113 ASP Shell ]"
	$s50 = "ASP Shell"
	$s51 = "Hacked by @iSecGroup"
	$s52 = "@iSecGroup"
	$s53 = "Lulzsecroot"
	$s54 = "KingDefacer"
	$s55 = "Turkish H4CK3RZ"
	$s56 = "by q1w2e3r4"
	$s57 = "By Ironfist"
	$s58 = "AK-74 Security"
	$s59 = "ak74-team.net"
	$s60 = "ANTICHAT.RU" nocase
	$s61 = "ADMINSTRATORS TOOLKIT"
	$s62 = "ASPSpyder"
	$s63 = "Shell v 2.1 Biz"
	$s64 = "Ayyildiz Tim"
	$s65 = "b374k"
	$s66 = "Cool Surfer"
	$s67 = "vINT 21h"
	$s68 = "c0derz shell"
	$s69 = "Emperor Hacking TEAM"
	$s70 = "Comandos Exclusivos"
	$s71 = "Gamma Group"
	$s72 = "GFS Web-Shell"
	$s73 = "Group Freedom Search"
	$s74 = "h4ntu shell"
	$s75 = "powered by tsoi"
	$s76 = "SaNaLTeRoR"
	$s77 = "inDEXER"
	$s78 = "ReaDer"
	$s79 = "JspWebshell"
	$s80 = "zero.cnbct.org"
	$s81 = "Aventis KlasVayv"
	$s82 = "KlasVayv" nocase
	$s825 = "Kodlama by BLaSTER"
	$s83 = "TurkGuvenligi"
	$s84 = "BLaSTER"
	$s85 = "lama's'hell"
	$s86 = "Liz0ziM"
	$s87 = "Loader'z WEB Shell"
	$s88 = "Loader Pro-Hack.ru"
	$s89 = "D3vilc0de"
	$s90 = "lostDC shell"
	$s91 = "MAX666"
	$s92 = "Hacked by Silver"
	$s93 = ".:NCC:."
	$s94 = "National Cracker Crew"
	$s95 = "n-c-c.6x.to"
	$s96 = "Cr4sh_aka_RKL"
	$s97 = "PHANTASMA"
	$s98 = "NeW CmD"
	$s99 = "z0mbie"
	$s100 = "phpRemoteView"
	$s101 = "php.spb.ru"
	$s102 = "Mehdi"
	$s103 = "HolyDemon"
	$s104 = "infilak"
	$s105 = "Rootshell"
	$s106 = "Emperor"
	$s107 = "Iranian Hackers"
	$s108 = "G-Security"
	$s109 = "by DK"
	$s110 = "Simorgh"
	$s111 = "SimShell"
	$s112 = "AventGrup"
	$s113 = "Sincap"
	$s114 = "zyklon"
	$s115 = "lovealihack"
	$s116 = "alihack"
condition:
	not uint16(0) == 0x5A4D and any of ($s*)
}

rule windows_credentials_editor
{
meta:
	author = "@patrickrolsen"
	reference = "http://www.ampliasecurity.com/research/wce12_uba_ampliasecurity_eng.pdf"
	filetype = "EXE"
	version = "0.1"
	date = "1/30/2014"
strings:
	$s1 = "NTLMCredentials"
	$s2 = "%d kerberos"
	$s3 = "WCE" nocase
	$s4 = "LSASS.EXE" nocase
condition:
	uint16(0) == 0x5A4D and (all of ($s*))
}

rule winrar_4xx
{
meta:
	author = "@patrickrolsen"
	reference = "WinRar 4.11 CMD line version"
	filetype = "EXE"
	version = "0.1"
	date = "1/30/2014"
strings:
	$s1 = "\\WinRAR\\rar\\"
	$s2 = "WinRAR"
condition:
	uint16(0) == 0x5A4D and (all of ($s*))
}

rule wp_shell_crew
{
meta:
	author = "@patrickrolsen"
	reference = "http://www.emc.com/collateral/white-papers/h12756-wp-shell-crew.pdf"
	filetype = "EXE"
	version = "0.1"
	date = "1/29/2014"
strings:
	$mz = { 4d 5a } // MZ
	$s1 = "IsWow64Process"
	$s2 = "svchost.exe -k netsvcs"
	$s3 = "Services\\%s\\Parameters"
	$s4 = "%s %s %s"
	$s5 = "-%s-%03d"
	$s6 = "127.0.0.1"
	$s7 = "\\temp\\" fullword
condition:
	($mz at 0) and (all of ($s*))
}

rule zend_framework
{
meta:
	author = "@patrickrolsen"
	maltype = "Zend Framework"
	version = "0.3"
	date = "12/29/2013"
strings:
	$php = "<?php"
	$s = "$zend_framework" nocase
condition:
	not uint16(0) == 0x5A4D and $php and $s
}

rule rtf_Kaba_jDoe
{
meta:
	author = "@patrickrolsen"
	maltype = "APT.Kaba"
	filetype = "RTF"
	version = "0.1"
	description = "https://github.com/1aN0rmus/Yara"
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
	description = "https://github.com/1aN0rmus/Yara"
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
	description = "https://github.com/1aN0rmus/Yara"
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

rule backdoor_apt_pcclient
{
meta:
	author = "@patrickrolsen"
	maltype = "APT.PCCLient"
	filetype = "DLL"
	version = "0.1"
	description = "https://github.com/1aN0rmus/Yara"
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

