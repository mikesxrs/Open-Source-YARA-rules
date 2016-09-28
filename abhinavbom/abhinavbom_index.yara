

//PlugX APT Malware

rule PlugXXOR
{
meta:
	author = "@abhinavbom"
	maltype = "NA"
	version = "0.1"
	date = "21/09/2015"
     description = "rule for PlugX XOR Routine"
     ref1 = "7048add2873b08a9693a60135f978686"
strings:
     $hex_string = { 05 ?? ?? 00 00 8A D8 2A DC 89 45 FC 32 5D FE 81 E9 ?? ?? 00 00 2A 5D FF 89 4D F8 32 D9 2A DD 32 5D FA 2A 5D FB 32 1C 37 88 1E 46 4A 75 D2 5F 5B }
condition:
     all of them
}
 
 
 //APT1-Group Rule for sample used during exercise
 
rule BOUNCER_APT1 {
meta:
     author = "@abhinavbom"
	maltype = "NA"
	version = "0.1"
	date = "21/09/2015"
     info = "CommentCrew-threat-apt1"
strings:
     $s1 = "*Qd9kdgba33*%Wkda0Qd3kvn$*&><(*&%$E#%$#1234asdgKNAg@!gy565dtfbasdg" wide ascii
     $s2 = "IDR_DATA%d" wide ascii
     $s3 = "asdfqwe123cxz" wide ascii
     $s4 = "Mode must be 0(encrypt) or 1(decrypt)." wide ascii
condition:
     ($s1 and $s2) or ($s3 and $s4)

}

rule banbra : banker
{
meta: 
    author = "@abhinavbom"
	maltype = "NA"
	version = "0.1"
	date = "8/06/2015"
strings: 
    $a = "senha" fullword nocase
    $b = "cartao" fullword nocase
    $c = "caixa" 
    $d = "login" fullword nocase
    $e = ".com.br"

condition:
    #a > 3 and #b > 3 and #c > 3 and #d > 3 and #e > 3              
}

/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as long as you use it under this license.

*/

/* Certificate Matches for Patterns seen in Duqu 2.0 infection */

/* https://securelist.com/files/2015/06/The_Mystery_of_Duqu_2_0_a_sophisticated_cyberespionage_actor_returns.pdf */

import "pe"
rule honhaicert_goodcheck {
	strings:
		$honhai = "HON HAI"
	condition:
		$honhai and pe.version_info["LegalCopyright"] contains "Microsoft"
}



rule sysinternals_not_signed
{
strings:
       $sysinternals = "sysinternals" wide nocase
       $mz = "MZ"
       $url = "technet.microsoft.com" wide 
       $castuff = "Microsoft Code Signing PCA" wide

condition:
       $mz at 0 and $sysinternals and ( not $castuff and not $url)
}

rule Gh0stRAT
{
meta:
	author = "@abhinavbom"
	maltype = "NA"
	version = "0.1"
	date = "21/09/2015"
    description = "rule for Gh0stRAT 3.6 variant June 2015"
    originalauthor = "John Petrequin (jpetrequin@wapacklabs.com)"
    ref1 = "http://researchcenter.paloaltonetworks.com/2015/09/musical-chairs-multi-year-campaign-involving-new-variant-of-gh0st-malware/"
    ref2= "1d7cb7250cf14ed2b9e1c99facba55df"
strings:
    $MZ = "MZ"
    $a = "piano.dll"
    $b1 = "Programed by Zhou Zhangfa" wide
    $b2 = "Please check your Sound Galaxy card." wide
condition:
    $MZ and $a and any of ($b*)
}

rule FastPOS
{
meta:
	author = "@abhinavbom"
	maltype = "NA"
	version = "0.1"
	date = "06/10/2016"
  description = "rule to detect FastPOS Mutex"
  ref1 = "5aabd7876faba0885fccc8b4d095537bd048b6943aaacaf3e01d204450e787c6"

strings:
  $string1 = "uniqyeidclaxemain"
  $string2 = "http://%s/cdosys.php"
  
condition:        
  all of ($string*)
  
}

//Rule to Catch Intelligence files in the meta of files uploaded. Current rule looks for NSA and MOSAD in meta of samples.

rule catch_intelligence_files
{
meta:
	author = "@abhinavbom"
	maltype = "NA"
	version = "0.1"
	date = "21/09/2015"
    description = "catch files"
strings:
    $meta1 = "National Security Agency"
    $meta3 = "Israeli Secret Intelligence"
    $tag1 = "docx"
	$tag2 = "doc"
	$tag3 = "xls"
	$tag4 = "xlxs"
	$tag5 = "pdf"
	$tag6 = "zip"
	$tag7 = "rar"
    $tag8 = "xlsb"

condition:
    any of ($meta*) and any of ($tag*)
}

//Rule to pick up all the pcaps uploaded to Virustotal. This rule can be very noisy. 

rule FE_PCAPs
{
meta:
	author = "@abhinavbom"
	maltype = "NA"
	version = "0.1"
	description = "All pcaps uploaded to VT"
	date = "29/07/2015"
strings:
	$magic = {D4 C3 B2 A1}
condition:
	$magic at 0
}

//Rule to detect all pcap uploads to Virustotal with +3 detection.

rule pcap_positives
{
meta:
	author = "@abhinavbom"
	maltype = "NA"
	version = "0.1"
	description = "All pcaps uploaded to VT with +3 detection rate"
	date = "21/06/2015"
strings:
	$magic = {D4 C3 B2 A1}
condition:
	$magic at 0 and positives > 3
}

//Rule to detect All pcaps submitted to VT and tagged as Exploit kits.

rule ek_submissions				
{
meta:
	author = "@abhinavbom"
	maltype = "NA"
	version = "0.1"
	description = "Detects pcaps uploaded to VT and matches IDS detections for Exploit kits"
	date = "23/06/2015"
strings:
	$magic = {D4 C3 B2 A1}
condition:
	$magic at 0 and tags contains "exploit-kit"
}

//EK detection in VT for +3 positive engine detections

rule ek_submissions_2				
{
meta:
	author = "@abhinavbom"
	maltype = "NA"
	version = "0.1"
	description = "Detects pcaps uploaded to VT and matches IDS detections for Exploit kits"
	date = "23/06/2015"
strings:
	$magic = {D4 C3 B2 A1}
condition:
	$magic at 0 and tags contains "exploit-kit" and positives >3
}

rule vmdetect_misc : vmdetect
{
	meta:
    		author = "@abhinavbom"
		maltype = "NA"
		version = "0.1"
		date = "31/10/2015"
		description = "Following Rule is referenced from AlienVault's Yara rule repository.This rule contains additional processes and driver names."
	strings:
		$vbox1 = "VBoxService" nocase ascii wide
		$vbox2 = "VBoxTray" nocase ascii wide
		$vbox3 = "SOFTWARE\\Oracle\\VirtualBox Guest Additions" nocase ascii wide
		$vbox4 = "SOFTWARE\\\\Oracle\\\\VirtualBox Guest Additions" nocase ascii wide

		$wine1 = "wine_get_unix_file_name" ascii wide

		$vmware1 = "vmmouse.sys" ascii wide
		$vmware2 = "VMware Virtual IDE Hard Drive" ascii wide

		$miscvm1 = "SYSTEM\\ControlSet001\\Services\\Disk\\Enum" nocase ascii wide
		$miscvm2 = "SYSTEM\\\\ControlSet001\\\\Services\\\\Disk\\\\Enum" nocase ascii wide

		// Drivers
		$vmdrv1 = "hgfs.sys" ascii wide
		$vmdrv2 = "vmhgfs.sys" ascii wide
		$vmdrv3 = "prleth.sys" ascii wide
		$vmdrv4 = "prlfs.sys" ascii wide
		$vmdrv5 = "prlmouse.sys" ascii wide
		$vmdrv6 = "prlvideo.sys" ascii wide
		$vmdrv7 = "prl_pv32.sys" ascii wide
		$vmdrv8 = "vpc-s3.sys" ascii wide
		$vmdrv9 = "vmsrvc.sys" ascii wide
		$vmdrv10 = "vmx86.sys" ascii wide
		$vmdrv11 = "vmnet.sys" ascii wide

		// SYSTEM\ControlSet001\Services
		$vmsrvc1 = "vmicheartbeat" ascii wide
		$vmsrvc2 = "vmicvss" ascii wide
		$vmsrvc3 = "vmicshutdown" ascii wide
		$vmsrvc4 = "vmicexchange" ascii wide
		$vmsrvc5 = "vmci" ascii wide
		$vmsrvc6 = "vmdebug" ascii wide
		$vmsrvc7 = "vmmouse" ascii wide
		$vmsrvc8 = "VMTools" ascii wide
		$vmsrvc9 = "VMMEMCTL" ascii wide
		$vmsrvc10 = "vmware" ascii wide
		$vmsrvc11 = "vmx86" ascii wide
		$vmsrvc12 = "vpcbus" ascii wide
		$vmsrvc13 = "vpc-s3" ascii wide
		$vmsrvc14 = "vpcuhub" ascii wide
		$vmsrvc15 = "msvmmouf" ascii wide
		$vmsrvc16 = "VBoxMouse" ascii wide
		$vmsrvc17 = "VBoxGuest" ascii wide
		$vmsrvc18 = "VBoxSF" ascii wide
		$vmsrvc19 = "xenevtchn" ascii wide
		$vmsrvc20 = "xennet" ascii wide
		$vmsrvc21 = "xennet6" ascii wide
		$vmsrvc22 = "xensvc" ascii wide
		$vmsrvc23 = "xenvdb" ascii wide

		// Processes
		$miscproc1 = "vmware2" ascii wide
		$miscproc2 = "vmount2" ascii wide
		$miscproc3 = "vmusrvc" ascii wide
		$miscproc4 = "vmsrvc" ascii wide
		$miscproc5 = "vboxservice" ascii wide
		$miscproc6 = "vboxtray" ascii wide
		$miscproc7 = "xenservice" ascii wide

		$vmware_mac_1a = "00-05-69"
		$vmware_mac_1b = "00:05:69"
		$vmware_mac_2a = "00-50-56"
		$vmware_mac_2b = "00:50:56"
		$vmware_mac_3a = "00-0C-29"
		$vmware_mac_3b = "00:0C:29"
		$vmware_mac_4a = "00-1C-14"
		$vmware_mac_4b = "00:1C:14"
		$virtualbox_mac_1a = "08-00-27"
		$virtualbox_mac_1b = "08:00:27"

	condition:
		2 of them
}

rule xmlshell{
meta:
	author = "@abhinavbom"
	maltype = "NA"
	version = "0.1"
	date = "21/09/2015"
    description = "strings within XMLShell used by CommentCrew"
strings:
	$STFail = "ST fail"
	$STSucc = "ST Success"
	$Proc = "Process cmd.exe exited"
	$ShellSuccess = "Shell started successfully"
	$ShellFail = "Shell started fail"
	$KillFail = "Kill Fail"
	$KillSucc = "Kill Success"
condition:
	all of them
}



