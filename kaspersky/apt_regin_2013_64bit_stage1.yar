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