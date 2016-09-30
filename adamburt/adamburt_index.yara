rule shellshock_generic

{
meta:
author="Adam Burt"
strings:
$starter = "() { "
$alt1 = "(a)=>"
$alt2 = ":; } ;"
$att1 = "HOLD Flooding"
$att2 = "JUNK Flooding"
$att4 = "PONG!"
$att5 = "/bin/busybox"
$att6 = "SCANNER"
condition:
( $starter and any of ($alt*) ) or ( all of ($att*) )
}
rule BackOffPOS_1_56_LAST
{
meta:
	description = "BackoffPOS 1.56 LAST process injection code detection"
	in_the_wild = true

strings:
$a = {E8 00 00 00 00 5D 81 ED 05 00 00 00 31 C9 64 8B 71 30 8B 76 0C 8B 76 1C 8B 5E 08 8B 7E 20 8B 36 66 39 4F 18 75 F2 8D BD E3 05 00 00 89 FE B9 0E 00 00 00 AD E8 15 02 00 00 AB E2 F7 8D 85 D0 03 00 00 50 6A 00 6A 00 FF 95 EB 05 00 00 8D 85 99 03 00 00 50 FF 95 FF 05 00 00 85 C0 0F 84 D5 01 00 00 8D 9D A5 03 00 00 53 50 FF 95 FB 05 00 00 85 C0 0F 84 BF 01 00 00 89 85 DF 05 00 00 8D BD DD 03 00 00 6A 00 6A 1A 57 6A 00 FF 95 DF 05 00 00 89 FE E8 A7 01 00 00 01 C7 B9 09 00 00 00 8D B5 82 03 00 00 F3 A4 8D BD DC 04 00 00 6A 00 6A 1A 57 6A 00 FF 95 DF 05 00 00 89 FE E8 7E 01 00 00 01 C7 B9 0E 00 00 00 8D B5 8B 03 00 00 F3 A4 8D 85 72 03 00 00 50 6A 00 68 01 00 1F 00 FF 95 03 06 00 00 85 C0 74 14 50 FF 95 E3 05 00 00 68 E0 93 04 00 FF 95 0B 06 00 00 EB D4 8D 85 DD 03 00 00 6A 00 68 80 00 00 00 6A 03 6A 00 6A 00 68 00 00 00 80 50 FF 95 E7 05 00 00 83 F8 FF 0F 84 03 01 00 00 89 C3 6A 00 50 FF 95 F7 05 00 00 83 F8 FF 0F 84 E8 00 00 00 89 C7 6A 04 68 00 30 00 00 50 6A 00 FF 95 0F 06 00 00 85 C0 0F 84 CE 00 00 00 89 C6 8D 85 DB 05 00 00 6A 00 50 57 56 53 FF 95 07 06 00 00 85 C0 0F 84 B2 00 00 00 53 FF 95 E3 05 00 00 8D 85 6A 03 00 00 50 57 56 E8 28 01 00 00 8D 85 DC 04 00 00 6A 00 68 80 00 00 00 6A 02 6A 00 6A 00 68 00 00 00 40 50 FF 95 E7 05 00 00 83 F8 FF 74 29 89 C3 8D 85 DB 05 00 00 6A 00 50 57 56 53 FF 95 17 06 00 00 53 FF 95 E3 05 00 00 68 00 80 00 00 6A 00 56 FF 95 13 06 00 00 8D 85 99 03 00 00 50 FF 95 FF 05 00 00 8D 9D BD 03 00 00 53 50 FF 95 FB 05 00 00 8D 9D CB 03 00 00 8D BD DC 04 00 00 6A 00 6A 00 6A 00 57 53 6A 00 FF D0 68 E0 93 04 00 FF 95 0B 06 00 00 8D BD DC 04 00 00 57 FF 95 F3 05 00 00 E9 B0 FE FF FF 53 FF 95 E3 05 00 00 68 E0 93 04 00 FF 95 0B 06 00 00 E9 99 FE FF FF 6A 00 FF 95 EF 05 00 00 53 31 C0 8A 1C 06 84 DB 74 03 40 EB F6 5B C3 55 89 E5 83 EC 0C 60 89 5D FC 89 45 F8 03 5B 3C 8B 5B 78 03 5D FC 8B 7B 20 03 7D FC 31 F6 8D 14 B7 8B 12 03 55 FC 31 C0 C1 C0 07 32 02 42 80 3A 00 75 F5 3B 45 F8 74 06 46 3B 73 18 72 E0 8B 53 24 03 55 FC 0F B7 14 72 8B 43 1C 03 45 FC 8B 04 90 03 45 FC 89 45 F4 61 8B 45 F4 C9 C3 55 89 E5 57 56 53 81 EC 04 01 00 00 31 C0 88 84 28 F4 FE FF FF 40 3D 00 01 00 00 75 F1 8D 8D F4 FE FF FF 8D 7D F4 31 D2 31 DB 8A 01 88 85 F2 FE FF FF 8B 75 10 02 04 32 01 C3 0F B6 DB 8A 84 2B F4 FE FF FF 88 01 8A 85 F2 FE FF FF 88 84 2B F4 FE FF FF 8D 42 01 BE 08 00 00 00 99 F7 FE 41 39 F9 75 C7 31 C9 31 D2 31 C0 EB 42 42 81 E2 FF 00 00 00 0F B6 BC 2A F4 FE FF FF 01 F9 0F B6 C9 0F B6 B4 29 F4 FE FF FF 89 F3 88 9C 2A F4 FE FF FF 89 FB 88 9C 29 F4 FE FF FF 8D 1C 37 0F B6 DB 8A 9C 2B F4 FE FF FF 8B 75 08 30 1C 30 40 3B 45 0C 7C B9 81 C4 04 01 00 00 5B 5E 5F 5D C2 0C 00 }
$b = {50 61 73 73 77 6F 72 64 }
$c = {6E 73 6B 61 6C }
$d = {77 69 6E 73 65 72 76 73 2E 65 78 65 }
$e = {73 68 65 6C 6C 33 32 2E 64 6C 6C 00 53 48 47 65 74 53 70 65 63 69 61 6C 46 6F 6C 64 65 72 50 61 74 68 41 00 53 68 65 6C 6C 45 78 65 63 75 74 65 41 }

condition:

all of them

}

rule BackOffPOS_1_55_DEC
{
meta:
	description = "BackoffPOS 1.56 LAST process injection code detection"
	in_the_wild = true

strings:
$a = "dec"
$b = "1.55"
$d = "Update"
$e = "Terminate"
$f = "Upload KeyLogs"
$g = "[Enter]"

condition:

all of them

}

rule BackOffPOS_GENERIC
{
meta:
	description = "BackoffPOS generic catcher for known strings"
	in_the_wild = true

strings:
$a = "Update"
$b = "Terminate"
$d = "Uninstall"
$e = "Download"
$f = "Run"
$g = "Upload"
$h = "KeyLogs"
$i = "Password"
$j = "USERNAME"
$k = "[Enter]"
$l = "Log"

condition:

all of them

}
rule Dexter
{
meta:
	description = "Dexter malware memory injection detection"
	in_the_wild = true

strings:
$a = "Resilience"
$b = "download-"
$c = "update-"
$d = "checkin:"
$e = "uninstall"
$f = "CurrentVersion\\Run"
$g = "response="
$h = "gateway.php"
$i = "iexplore.exe"

condition:

all of them

}
import "pe"

rule metasploit_payload_msfpayload
{
	meta:
		description = "This rule detects generic metasploit callback payloads generated with msfpayload"
		Author = "Adam Burt (adam_burt@symantec.com)"
	strings:
		$a1 = "asf"
		$a2 = "release"
		$a3 = "build"
		$a4 = "support"
		$a5 = "ab.pdb"
		$l1 = "WS2_32.dll"
		$l2 = "mswsock"
		$l3 = "ntdll.dll"
		$l4 = "KERNEL32.dll"
		$l5 = "shell32"
		$l6 = "malloc"
		$l7 = "fopen"
		$l8 = "fclose"
		$l9 = "fprintf"
		$l10 = "strncpy"
	condition:
		all of ($l*)
		and all of ($a*)

}


rule metasploit_service_starter
{
	meta:
		description = "This rule detects related metasploit service starters"
		author = "Adam Burt (adam_burt@symantec.com)"
	strings:
		$a1 = "StartServiceCtrlDispatcher"
		$a2 = "RegisterServiceCtrlHandle"
		$a3 = "CloseHandle"
		$a4 = "memset"
		$a5 = "rundll32.exe"
		$a6 = "msvcrt.dll"
	condition:
		pe.sections[3].name == ".bss"
		and pe.sections[3].virtual_size == 0x00000030
		and pe.sections[2].virtual_size == 0x0000001c
		and pe.sections[4].virtual_size == 0x00000224
		and all of them
}
rule trojan_poweliks_dropper
{
meta:
author = "Adam Burt (adam_burt@symantec.com)"
md5hash = "181dbed16bce32a7cfc15ecdd6e31918"
sha1hash = "b00a9e4e12f799a1918358d175f571439fc4b45c"

strings:
$s1 = "NameOfMutexObject"
$c1 = {2F 2E 6D 2C}
$c2 = {76 AB 0B A7}


condition:
$c1 at 0x104a0 or ($s1 and $c2 at 0x104a8)
}
