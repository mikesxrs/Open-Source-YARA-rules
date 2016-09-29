rule apt_duqu2_drivers {

meta:

		copyright = "Kaspersky Lab"
		description = "Rule to detect Duqu 2.0 drivers"
		last_modified = "2015-06-09"
		version = "1.0"
		Reference = "https://securelist.com/blog/research/70504/the-mystery-of-duqu-2-0-a-sophisticated-cyberespionage-actor-returns/"

strings:

		$a1="\\DosDevices\\port_optimizer" wide nocase
		$a2="romanian.antihacker"
		$a3="PortOptimizerTermSrv" wide
		$a4="ugly.gorilla1"

		$b1="NdisIMCopySendCompletePerPacketInfo"
		$b2="NdisReEnumerateProtocolBindings"
		$b3="NdisOpenProtocolConfiguration"

condition:

		uint16(0) == 0x5A4D and (any of ($a*) ) and (2 of ($b*)) and filesize < 100000

}

rule apt_duqu2_loaders {

meta:
		copyright = "Kaspersky Lab"
		description = "Rule to detect Duqu 2.0 samples"
		last_modified = "2015-06-09"
		version = "1.0"
		Reference = "https://securelist.com/blog/research/70504/the-mystery-of-duqu-2-0-a-sophisticated-cyberespionage-actor-returns/"

strings:

		$a1="{AAFFC4F0-E04B-4C7C-B40A-B45DE971E81E}" wide
		$a2="\\\\.\\pipe\\{AAFFC4F0-E04B-4C7C-B40A-B45DE971E81E}" wide
		$a4="\\\\.\\pipe\\{AB6172ED-8105-4996-9D2A-597B5F827501}" wide
		$a5="Global\\{B54E3268-DE1E-4c1e-A667-2596751403AD}" wide
		$a8="SELECT `Data` FROM `Binary` WHERE `Name`='%s%i'" wide
		$a9="SELECT `Data` FROM `Binary` WHERE `Name`='CryptHash%i'" wide
		$a7="SELECT `%s` FROM `%s` WHERE `%s`='CAData%i'" wide
		$b1="MSI.dll"
		$b2="msi.dll"
		$b3="StartAction"
		$c1="msisvc_32@" wide
		$c2="PROP=" wide
		$c3="-Embedding" wide
		$c4="S:(ML;;NW;;;LW)" wide

		$d1 = "NameTypeBinaryDataCustomActionActionSourceTargetInstallExecuteSequenceConditionSequencePropertyValueMicrosoftManufacturer" nocase
		$d2 = {2E 3F 41 56 3F 24 5F 42 69 6E 64 40 24 30 30 58 55 3F 24 5F 50 6D 66 5F 77 72 61 70 40 50 38 43 4C 52 ?? 40 40 41 45 58 58 5A 58 56 31 40 24 24 24 56 40 73 74 64 40 40 51 41 56 43 4C 52 ?? 40 40 40 73 74 64 40 40}
condition:

( (uint16(0) == 0x5a4d) and ( (any of ($a*)) or (all of ($b*)) or (all of ($c*)) ) and filesize < 100000 )

or

( (uint32(0) == 0xe011cfd0) and ( (any of ($a*)) or (all of ($b*)) or (all of ($c*)) or (any of ($d*)) ) and filesize < 20000000 )
}

rule apt_equation_exploitlib_mutexes {
 
meta:
 
    copyright = "Kaspersky Lab"
    description = "Rule to detect Equation group's Exploitation library"
    version = "1.0"
    last_modified = "2015-02-16"
    reference = "https://securelist.com/blog/research/68750/equation-the-death-star-of-malware-galaxy/"
 
 
strings:
 
    $mz="MZ"
 
    $a1="prkMtx" wide
    $a2="cnFormSyncExFBC" wide
    $a3="cnFormVoidFBC" wide
    $a4="cnFormSyncExFBC" 
    $a5="cnFormVoidFBC"
 
condition:
 
(($mz at 0) and any of ($a*))

}

rule apt_equation_doublefantasy_genericresource {
    meta:
        copyright = "Kaspersky Lab"
        description = "Rule to detect DoubleFantasy encoded config http://goo.gl/ivt8EW"
        version = "1.0"
        last_modified = "2015-02-16"
        reference = "http://securelist.com/blog/research/68750/equation-the-death-star-of-malware-galaxy/"
    strings:
        $mz="MZ"
        $a1={06 00 42 00 49 00 4E 00 52 00 45 00 53 00}
        $a2="yyyyyyyyyyyyyyyy"
        $a3="002"
    condition:
        (($mz at 0) and all of ($a*)) and filesize < 500000
}

rule apt_equation_equationlaser_runtimeclasses {
	meta:
	    copyright = "Kaspersky Lab"
	    description = "Rule to detect the EquationLaser malware"
	    version = "1.0"
	    last_modified = "2015-02-16"
	    reference = "http://securelist.com/blog/research/68750/equation-the-death-star-of-malware-galaxy/"
	strings:
	    $a1="?a73957838_2@@YAXXZ"
	    $a2="?a84884@@YAXXZ"
	    $a3="?b823838_9839@@YAXXZ"
	    $a4="?e747383_94@@YAXXZ"
	    $a5="?e83834@@YAXXZ"
	    $a6="?e929348_827@@YAXXZ"
	condition:
	    any of them
}

rule apt_equation_cryptotable : crypto {
	meta:
	    copyright = "Kaspersky Lab"
	    description = "Rule to detect the crypto library used in Equation group malware"
	    version = "1.0"
	    last_modified = "2015-02-16"
	    reference = "http://securelist.com/blog/research/68750/equation-the-death-star-of-malware-galaxy/"
	strings:
	    $a={37 DF E8 B6 C7 9C 0B AE 91 EF F0 3B 90 C6 80 85 5D 19 4B 45 44 12 3C E2 0D 5C 1C 7B C4 FF D6 05 17 14 4F 03 74 1E 41 DA 8F 7D DE 7E 99 F1 35 AC B8 46 93 CE 23 82 07 EB 2B D4 72 71 40 F3 B0 F7 78 D7 4C D1 55 1A 39 83 18 FA E1 9A 56 B1 96 AB A6 30 C5 5F BE 0C 50 C1}
	condition:
	    $a
}

rule apt_hellsing_implantstrings 
{
	meta:
		version = "1.0"
		filetype = "PE"
		author = "Costin Raiu, Kaspersky Lab"
		copyright = "Kaspersky Lab"
		date = "2015-04-07"
		description = "detection for Hellsing implants"

	strings:
 		$mz="MZ"
 		$a1="the file uploaded failed !"
 		$a2="ping 127.0.0.1"
 		$b1="the file downloaded failed !"
 		$b2="common.asp"
 		$c="xweber_server.exe"
 		$d="action="
		$debugpath1="d:\\Hellsing\\release\\msger\\" nocase
		$debugpath2="d:\\hellsing\\sys\\xrat\\" nocase
		$debugpath3="D:\\Hellsing\\release\\exe\\" nocase
		$debugpath4="d:\\hellsing\\sys\\xkat\\" nocase
		$debugpath5="e:\\Hellsing\\release\\clare" nocase
		$debugpath6="e:\\Hellsing\\release\\irene\\" nocase
		$debugpath7="d:\\hellsing\\sys\\irene\\" nocase
		$e="msger_server.dll"
		$f="ServiceMain"

	condition:
		($mz at 0) and (all of ($a*)) or (all of ($b*)) or ($c and $d) or (any of ($debugpath*)) or ($e and $f) and filesize < 500000
}

rule apt_hellsing_installer 
{
	meta:
		version = "1.0"
		filetype = "PE"
		author = "Costin Raiu, Kaspersky Lab"
		copyright = "Kaspersky Lab"
		date = "2015-04-07"
		description = "detection for Hellsing xweber/msger installers"

	strings:
		$mz="MZ"
		$cmd="cmd.exe /c ping 127.0.0.1 -n 5&cmd.exe /c del /a /f \"%s\""
		$a1="xweber_install_uac.exe"
		$a2="system32\\cmd.exe" wide
		$a4="S11SWFOrVwR9UlpWRVZZWAR0U1aoBHFTUl2oU1Y="
		$a5="S11SWFOrVwR9dnFTUgRUVlNHWVdXBFpTVgRdUlpWRVZZWARdUqhZVlpFR1kEUVNSXahTVgRaU1YEUVNSXahTVl1SWwRZValdVFFZUqgQBF1SWlZFVllYBFRTVqg="
		$a6="7dqm2ODf5N/Y2N/m6+br3dnZpunl44g="
		$a7="vd/m7OXd2ai/5u7a59rr7Ki45drcqMPl5t/c5dqIZw=="
		$a8="vd/m7OXd2ai/usPl5qjY2uXp69nZqO7l2qjf5u7a59rr7Kjf5tzr2u7n6euo4+Xm39zl2qju5dqo4+Xm39zl2t/m7ajr19vf2OPr39rj5eaZmqbs5OSI Njl2tyI"
		$a9="C:\\Windows\\System32\\sysprep\\sysprep.exe" wide
		$a10="%SystemRoot%\\system32\\cmd.exe" wide
		$a11="msger_install.dll"
		$a12={00 65 78 2E 64 6C 6C 00}

	condition:
		($mz at 0) and ($cmd and (2 of ($a*))) and filesize < 500000
}

rule apt_hellsing_irene 
{
	meta:
		version = "1.0"
		filetype = "PE"
		author = "Costin Raiu, Kaspersky Lab"
		copyright = "Kaspersky Lab"
		date = "2015-04-07"
		description = "detection for Hellsing msger irene installer"

	strings:
		$mz="MZ"
		$a1="\\Drivers\\usbmgr.tmp" wide
		$a2="\\Drivers\\usbmgr.sys" wide
		$a3="common_loadDriver CreateFile error! "
		$a4="common_loadDriver StartService error && GetLastError():%d! "
		$a5="irene" wide
		$a6="aPLib v0.43 - the smaller the better"

	condition:
		($mz at 0) and (4 of ($a*)) and filesize < 500000
}

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

rule apt_hellsing_proxytool 
{
	meta:
	version = "1.0"
	filetype = "PE"
	author = "Costin Raiu, Kaspersky Lab"
	copyright = "Kaspersky Lab"
	date = "2015-04-07"
	description = "detection for Hellsing proxy testing tool"

	strings:
		$mz="MZ"
		$a1="PROXY_INFO: automatic proxy url => %s "
		$a2="PROXY_INFO: connection type => %d "
		$a3="PROXY_INFO: proxy server => %s "
		$a4="PROXY_INFO: bypass list => %s "
		$a5="InternetQueryOption failed with GetLastError() %d"
		$a6="D:\\Hellsing\\release\\exe\\exe\\" nocase

	condition:
		($mz at 0) and (2 of ($a*)) and filesize < 300000
}

rule apt_hellsing_xkat 
{
	meta:
		version = "1.0"
		filetype = "PE"
		author = "Costin Raiu, Kaspersky Lab"
		copyright = "Kaspersky Lab"
		date = "2015-04-07"
		description = "detection for Hellsing xKat tool"

	strings:
		$mz="MZ"
		$a1="\\Dbgv.sys"
		$a2="XKAT_BIN"
		$a3="release sys file error."
		$a4="driver_load error. "
		$a5="driver_create error."
		$a6="delete file:%s error."
		$a7="delete file:%s ok."
		$a8="kill pid:%d error."
		$a9="kill pid:%d ok."
		$a10="-pid-delete"
		$a11="kill and delete pid:%d error."
		$a12="kill and delete pid:%d ok."

	condition:
		($mz at 0) and (6 of ($a*)) and filesize < 300000
}

rule apt_regin_2013_64bit_stage1 {

meta:
	copyright = "Kaspersky Lab"
	description = "Rule to detect Regin 64 bit stage 1 loaders"
	version = "1.0"
	last_modified = "2014-11-18"
	filename="wshnetc.dll"
	md5="bddf5afbea2d0eed77f2ad4e9a4f044d"
	filename="wsharp.dll"
	md5="c053a0a3f1edcbbfc9b51bc640e808ce"
	Reference = "https://securelist.com/files/2014/11/Kaspersky_Lab_whitepaper_Regin_platform_eng.pdf"

strings:
	$mz="MZ"
		$a1="PRIVHEAD"
		$a2="\\\\.\\PhysicalDrive%d"
		$a3="ZwDeviceIoControlFile"

condition:

	($mz at 0) and (all of ($a*)) and filesize < 100000

}

rule apt_regin_dispatcher_disp_dll {

meta:

	copyright = "Kaspersky Lab"
	description = "Rule to detect Regin disp.dll dispatcher"
	version = "1.0"
	last_modified = "2014-11-18"
	Reference = "https://securelist.com/files/2014/11/Kaspersky_Lab_whitepaper_Regin_platform_eng.pdf"

strings:
	$mz="MZ"
		 $string1="shit"
		 $string2="disp.dll"
		 $string3="255.255.255.255"
		 $string4="StackWalk64"
		 $string5="imagehlp.dll"

condition:

	($mz at 0) and (all of ($string*))
}

rule apt_regin_vfs {

meta:

	copyright = "Kaspersky Lab"
	description = "Rule to detect Regin VFSes"
	version = "1.0"
	last_modified = "2014-11-18"
	Reference = "https://securelist.com/files/2014/11/Kaspersky_Lab_whitepaper_Regin_platform_eng.pdf"

strings:

	$a1={00 02 00 08 00 08 03 F6 D7 F3 52}
	$a2={00 10 F0 FF F0 FF 11 C7 7F E8 52}
	$a3={00 04 00 10 00 10 03 C2 D3 1C 93}
	$a4={00 04 00 10 C8 00 04 C8 93 06 D8}

condition:

	($a1 at 0) or ($a2 at 0) or ($a3 at 0) or ($a4 at 0)
}

rule exploit_Silverlight_Toropov_Generic_XAP {
	
	meta:

		author = "Kaspersky Lab"
		filetype = "Win32 EXE"
		date = "2015-07-23"
		version = "1.0"
		Reference = "https://securelist.com/blog/research/73255/the-mysterious-case-of-cve-2016-0034-the-hunt-for-a-microsoft-silverlight-0-day/"

strings:

	$b2="Can't find Payload() address" ascii wide
	$b3="/SilverApp1;compoent/App.xaml" ascii wide
	$b4="Can't allocate ums after buf[]" ascii wide
	$b5="------------  START  ------------"

condition:

	((2 of ($b*)) )
}

import "pe"
rule xdedic_packed_syscan {
	meta:
		author = "Kaspersky Lab"
		company = "Kaspersky Lab"
		reference = "https://securelist.com/files/2016/06/xDedic_marketplace_ENG.pdf"
	strings:
		$a1 = "SysScan.exe" nocase ascii wide
	condition:
		uint16(0) == 0x5A4D
		and any of ($a*) and filesize > 1000000 and filesize <1200000 and
		pe.number_of_sections == 13 and pe.version_info["FileVersion"] contains "1.3.4."
}

rule xDedic_SysScan_unpacked {
	meta:
		author = " Kaspersky Lab"
		maltype = "crimeware"
		type ="crimeware"
		filetype = "Win32 EXE"
		date = "2016-03-14"
		reference = "https://securelist.com/files/2016/06/xDedic_marketplace_ENG.pdf"
		version = "1.0"
		hash = "fac495be1c71012682ebb27092060b43"
		hash = "e8cc69231e209db7968397e8a244d104"
		hash = "a53847a51561a7e76fd034043b9aa36d"
		hash = "e8691fa5872c528cd8e72b82e7880e98"
		hash = "F661b50d45400e7052a2427919e2f777"
	strings:
		$a1="/c ping -n 2 127.0.0.1 & del \"SysScan.exe\"" ascii wide
		$a2="SysScan DEBUG Mode!!!" ascii wide
		$a3="This rechecking? (set 0/1 or press enter key)" ascii wide
		$a4="http://37.49.224.144:8189/manual_result" ascii wide
		$b1="Checker end work!" ascii wide
		$b2="Trying send result..." ascii wide
	condition:
		((uint16(0) == 0x5A4D)) and (filesize < 5000000) and
		((any of ($a*)) or (all of ($b*)))
}

import "pe"
import "math"

rule apt_ProjectSauron_pipe_backdoor  {
meta:
	copyright = "Kaspersky Lab"
	description = "Rule to detect ProjectSauron pipe backdoors"
	version = "1.0"    
	reference = "https://securelist.com/blog/"
   
strings:

	$a1 = "CreateNamedPipeW" fullword ascii
	$a2 = "SetSecurityDescriptorDacl" fullword ascii
	$a3 = "GetOverlappedResult" fullword ascii
	$a4 = "TerminateThread" fullword ascii
	$a5 = "%s%s%X" fullword wide
	

condition:
	uint16(0) == 0x5A4D 
	and (all of ($a*))
	and filesize < 100000
}

rule apt_ProjectSauron_encrypted_LSA  {
meta:
	copyright = "Kaspersky Lab"
	description = "Rule to detect ProjectSauron encrypted LSA samples"
	version = "1.0"    
	reference = "https://securelist.com/blog/"

strings:

	$a1 = "EFEB0A9C6ABA4CF5958F41DB6A31929776C643DEDC65CC9B67AB8B0066FF2492" fullword ascii
	$a2 = "\\Device\\NdisRaw_" fullword ascii
	$a3 = "\\\\.\\GLOBALROOT\\Device\\{8EDB44DC-86F0-4E0E-8068-BD2CABA4057A}" fullword wide
	$a4 = "Global\\{a07f6ba7-8383-4104-a154-e582e85a32eb}" fullword wide
	$a5 = "Missing function %S::#%d" fullword wide
	$a6 = {8945D08D8598FEFFFF2BD08945D88D45BC83C20450C745C0030000008975C48955DCFF55FC8BF88D8F0000003A83F90977305333DB53FF15}
	$a7 = {488D4C24304889442450488D452044886424304889442460488D4520C7442434030000002BD848897C243844896C244083C308895C246841FFD68D880000003A8BD883F909772DFF}


condition:
	uint16(0) == 0x5A4D
	and (any of ($a*) or
	(
		pe.exports("InitializeChangeNotify") and
		pe.exports("PasswordChangeNotify") and
		math.entropy(0x400, filesize) >= 7.5
	))
	and filesize < 1000000
}

rule apt_ProjectSauron_encrypted_SSPI  {
meta:
	copyright = "Kaspersky Lab"
	description = "Rule to detect encrypted ProjectSauron SSPI samples"
	version = "1.0"
	reference = "https://securelist.com/blog/"

condition:
	uint16(0) == 0x5A4D and
	filesize < 1000000 and
	pe.exports("InitSecurityInterfaceA") and
	pe.characteristics & pe.DLL and
	(pe.machine == pe.MACHINE_AMD64 or pe.machine == pe.MACHINE_IA64) and
	math.entropy(0x400, filesize) >= 7.5     
}

rule apt_ProjectSauron_MyTrampoline  {
meta:
	copyright = "Kaspersky Lab"
	description = "Rule to detect ProjectSauron MyTrampoline module"
	version = "1.0"
	reference = "https://securelist.com/blog/"

strings:

	$a1 = ":\\System Volume Information\\{" wide
	$a2 = "\\\\.\\PhysicalDrive%d" wide
	$a3 = "DMWndClassX%d"

	$b1 = "{774476DF-C00F-4e3a-BF4A-6D8618CFA532}" ascii wide
	$b2 = "{820C02A4-578A-4750-A409-62C98F5E9237}" ascii wide

condition:
	uint16(0) == 0x5A4D and
	filesize < 5000000 and
	(all of ($a*) or any of ($b*))
}

rule apt_ProjectSauron_encrypted_container  {
meta:
	copyright = "Kaspersky Lab"
	description = "Rule to detect ProjectSauron samples encrypted container"
	version = "1.0"
	reference = "https://securelist.com/blog/"

strings:

	$vfs_header = {02 AA 02 C1 02 0?}
	$salt = {91 0A E0 CC 0D FE CE 36 78 48 9B 9C 97 F7 F5 55}

condition:
	uint16(0) == 0x5A4D
	and ((@vfs_header < 0x4000) or $salt) and
	math.entropy(0x400, filesize) >= 6.5 and
	(filesize > 0x400) and filesize < 10000000
}

rule apt_ProjectSauron_encryption  {
meta:
	copyright = "Kaspersky Lab"
	description = "Rule to detect ProjectSauron string encryption"
	version = "1.0"
	reference = "https://securelist.com/blog/"


strings:

	$a1 = {81??02AA02C175??8B??0685}
	$a2 = {918D9A94CDCC939A93939BD18B9AB8DE9C908DAF8D9B9BBE8C8C9AFF}
	$a3 = {803E225775??807E019F75??807E02BE75??807E0309}

condition:
	filesize < 5000000 and
	any of ($a*)
}

rule apt_ProjectSauron_generic_pipe_backdoor {
meta:
	copyright = "Kaspersky Lab"
	description = "Rule to detect ProjectSauron generic pipe backdoors"
	version = "1.0"
	reference = "https://securelist.com/blog/"

strings:
	$a = { C7 [2-3] 32 32 32 32 E8 }
	$b = { 42 12 67 6B }
	$c = { 25 31 5F 73 }
	$d = "rand"
	$e = "WS2_32"

condition:
	uint16(0) == 0x5A4D and
	(all of them) and
	filesize < 400000
}