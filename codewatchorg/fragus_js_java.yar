rule fragus_js_java
{
meta:
	author = "Josh Berry"
	date = "2016-06-26"
	description = "Fragus Exploit Kit Detection"
	hash0 = "7398e435e68a2fa31607518befef30fb"
	sample_filetype = "js-html"
	yaragenerator = "https://github.com/Xen0ph0n/YaraGenerator"
strings:
	$string0 = "I></XML><SPAN DATASRC"
	$string1 = "setTimeout('vparivatel()',8000);function vparivatel(){document.write('<iframe src"
	$string2 = "I DATAFLD"
	$string3 = " unescape("
	$string4 = ", 1);swf.setAttribute("
	$string5 = "function XMLNEW(){var spray "
	$string6 = "vparivatel.php"
	$string7 = "6) ){if ( (lv"
	$string8 = "'WIN 9,0,16,0')"
	$string9 = "d:/Program Files/Outlook Express/WAB.EXE"
	$string10 = "<XML ID"
	$string11 = "new ActiveXObject("
	$string12 = "'7.1.0') ){SHOWPDF('iepdf.php"
	$string13 = "function SWF(){try{sv"
	$string14 = "'WIN 9,0,28,0')"
	$string15 = "C DATAFORMATAS"
	$string16 = " shellcode;xmlcode "
	$string17 = "function SNAPSHOT(){var a"
condition:
	17 of them
}
