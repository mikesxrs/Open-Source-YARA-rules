rule phoenix_html4
{
meta:
	author = "Josh Berry"
	date = "2016-06-26"
	description = "Phoenix Exploit Kit Detection"
	hash0 = "61fde003211ac83c2884fbecefe1fc80"
	sample_filetype = "js-html"
	yaragenerator = "https://github.com/Xen0ph0n/YaraGenerator"
strings:
	$string0 = "/dr.php"
	$string1 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	$string2 = "launchjnlp"
	$string3 = "clsid:CAFEEFAC-DEC7-0000-0000-ABCDEFFEDCBA"
	$string4 = "urlmon.dll"
	$string5 = "<body>"
	$string6 = " docbase"
	$string7 = "</html>"
	$string8 = " classid"
	$string9 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	$string10 = "63AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	$string11 = "</object>"
	$string12 = "application/x-java-applet"
	$string13 = "java_obj"
condition:
	13 of them
}
