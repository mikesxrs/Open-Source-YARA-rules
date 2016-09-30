rule angler_flash5
{
meta:
	author = "Josh Berry"
	date = "2016-06-26"
	description = "Angler Exploit Kit Detection"
	hash0 = "9f809272e59ee9ecd71093035b31eec6"
	sample_filetype = "unknown"
	yaragenerator = "https://github.com/Xen0ph0n/YaraGenerator"
strings:
	$string0 = "0k%2{u"
	$string1 = "\\Pb@(R"
	$string2 = "ys)dVI"
	$string3 = "tk4_y["
	$string4 = "LM2Grx"
	$string5 = "n}s5fb"
	$string6 = "jT Nx<hKO"
	$string7 = "5xL>>}"
	$string8 = "S%,1{b"
	$string9 = "C'3g7j"
	$string10 = "}gfoh]"
	$string11 = ",KFVQb"
	$string12 = "LA;{Dx"
condition:
	12 of them
}
