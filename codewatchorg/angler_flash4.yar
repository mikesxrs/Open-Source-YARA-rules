rule angler_flash4
{
meta:
	author = "Josh Berry"
	date = "2016-06-26"
	description = "Angler Exploit Kit Detection"
	hash0 = "dbb3f5e90c05602d92e5d6e12f8c1421"
	sample_filetype = "unknown"
	yaragenerator = "https://github.com/Xen0ph0n/YaraGenerator"
strings:
	$string0 = "_u;cwD;"
	$string1 = "lhNp74"
	$string2 = "Y0GQ%v"
	$string3 = "qjqCb,nx"
	$string4 = "vn{l{Wl"
	$string5 = "5j5jz5"
	$string6 = "a3EWwhM"
	$string7 = "hVJb/4Aut"
	$string8 = ",lm4v,"
	$string9 = ",6MekS"
	$string10 = "YM.mxzO"
	$string11 = ";6 -$E"
	$string12 = "QA%: fy"
	$string13 = "<@{qvR"
	$string14 = "b9'$'6l"
	$string15 = ",x:pQ@-"
	$string16 = "2Dyyr9"
condition:
	16 of them
}
