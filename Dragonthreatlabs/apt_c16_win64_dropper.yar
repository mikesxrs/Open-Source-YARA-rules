rule apt_c16_win64_dropper 
{
	meta:
	     author = "@dragonthreatlab"
	     md5 = "ad17eff26994df824be36db246c8fb6a"
	     description = "APT malware used to drop PcClient RAT"
		 reference = "http://blog.dragonthreatlabs.com/2015/01/dtl-12012015-01-hong-kong-swc-attack.html"

	strings:
	     $str1 = "clbcaiq.dll" ascii
	     $str2 = "profapi_104" ascii
	     $str3 = "\\Microsoft\\wuauclt\\wuauclt.dat" ascii
	     $str4 = {0F B6 0A 48 FF C2 80 E9 03 80 F1 03 49 FF C8 88 4A FF 75 EC}
	     
	condition:
	     $mz at 0 and all of ($str*)

}