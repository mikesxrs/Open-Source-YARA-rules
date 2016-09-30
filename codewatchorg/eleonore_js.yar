rule eleonore_js
{
meta:
	author = "Josh Berry"
	date = "2016-06-26"
	description = "Eleonore Exploit Kit Detection"
	hash0 = "08f8488f1122f2388a0fd65976b9becd"
	sample_filetype = "js-html"
	yaragenerator = "https://github.com/Xen0ph0n/YaraGenerator"
strings:
	$string0 = "var de"
	$string1 = "sdjk];"
	$string2 = "return dfshk;"
	$string3 = "function jkshdk(){"
	$string4 = "'val';"
	$string5 = "var sdjk"
	$string6 = "return fsdjkl;"
	$string7 = " window[d"
	$string8 = "var fsdjkl"
	$string9 = "function jklsdjfk() {"
	$string10 = "function rewiry(yiyr,fjkhd){"
	$string11 = " sdjd "
condition:
	11 of them
}
