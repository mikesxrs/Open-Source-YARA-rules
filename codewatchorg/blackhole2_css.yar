rule blackhole2_css
{
meta:
	author = "Josh Berry"
	date = "2016-06-27"
	description = "BlackHole2 Exploit Kit Detection"
	hash0 = "9664a16c65782d56f02789e7d52359cd"
	sample_filetype = "js-html"
	yaragenerator = "https://github.com/Xen0ph0n/YaraGenerator"
strings:
	$string1 = "background:url('%%?a=img&img=countries.gif')"
	$string2 = "background:url('%%?a=img&img=exploit.gif')"
	$string3 = "background:url('%%?a=img&img=oses.gif')"
	$string4 = "background:url('%%?a=img&img=browsers.gif')"
	$string5 = "background:url('%%?a=img&img=edit.png')"
	$string6 = "background:url('%%?a=img&img=add.png')"
	$string7 = "background:url('%%?a=img&img=accept.png')"
	$string8 = "background:url('%%?a=img&img=del.png')"
	$string9 = "background:url('%%?a=img&img=stat.gif')"
condition:
	18 of them
}
