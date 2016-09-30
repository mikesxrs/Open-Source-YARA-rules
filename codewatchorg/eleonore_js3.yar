rule eleonore_js3
{
meta:
	author = "Josh Berry"
	date = "2016-06-26"
	description = "Eleonore Exploit Kit Detection"
	hash0 = "9dcb8cd8d4f418324f83d914ab4d4650"
	sample_filetype = "js-html"
	yaragenerator = "https://github.com/Xen0ph0n/YaraGenerator"
strings:
	$string0 = "@mozilla.org/file/directory_service;1"
	$string1 = "var exe "
	$string2 = "var file "
	$string3 = "foStream.write(data, data.length);"
	$string4 = "  var file_data "
	$string5 = "return "
	$string6 = " Components.classes["
	$string7 = "url : "
	$string8 = "].createInstance(Components.interfaces.nsILocalFile);"
	$string9 = "  var bstream "
	$string10 = " bstream.readBytes(size); "
	$string11 = "@mozilla.org/supports-string;1"
	$string12 = "  var channel "
	$string13 = "tmp.exe"
	$string14 = "  if (channel instanceof Components.interfaces.nsIHttpChannel "
	$string15 = "@mozilla.org/network/io-service;1"
	$string16 = " bstream.available()) { "
	$string17 = "].getService(Components.interfaces.nsIIOService); "
condition:
	17 of them
}
