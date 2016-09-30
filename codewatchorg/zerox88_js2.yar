rule zerox88_js2
{
meta:
	author = "Josh Berry"
	date = "2016-06-26"
	description = "0x88 Exploit Kit Detection"
	hash0 = "cad8b652338f5e3bc93069c8aa329301"
	sample_filetype = "js-html"
	yaragenerator = "https://github.com/Xen0ph0n/YaraGenerator"
strings:
	$string0 = "function gSH() {"
	$string1 = "200 HEIGHT"
	$string2 = "'sh.js'><\\/SCRIPT>"
	$string3 = " 2 - 26;"
	$string4 = "<IFRAME ID"
	$string5 = ",100);"
	$string6 = "200></IFRAME>"
	$string7 = "setTimeout("
	$string8 = "'about:blank' WIDTH"
	$string9 = "mf.document.write("
	$string10 = "document.write("
	$string11 = "Kasper "
condition:
	11 of them
}
