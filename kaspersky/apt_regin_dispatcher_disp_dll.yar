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
