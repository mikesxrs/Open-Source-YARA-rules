rule phoenix_html8
{
meta:
	author = "Josh Berry"
	date = "2016-06-26"
	description = "Phoenix Exploit Kit Detection"
	hash0 = "1c19a863fc4f8b13c0c7eb5e231bc3d1"
	sample_filetype = "js-html"
	yaragenerator = "https://github.com/Xen0ph0n/YaraGenerator"
strings:
	$string0 = "0x5)).replace(/"
	$string1 = "%A%%A%%nc(,145,9,84037,1711,,4121,56,1,,0505,,651,,3,514101,01,29,7868,90"
	$string2 = "/gmi,String.fromCharCode(2"
	$string3 = "turt;oo)s"
	$string4 = "91;var jtdpar"
	$string5 = "R(,13,7,63,48140601,5057,,319,,6,1,1,2,,110,0,1011171,2319,,,,10vEAs)tfmneyeh%A%%A%%A%%A%s<u91,4693,"
	$string6 = "y%%A%%A%%A%%A.meo21117,7,1,,10,1,9,8,1,9,100,6,141003,74181,163,441114,43,207,,remc'ut"
	$string7 = "epjtjqe){jtdpar"
	$string8 = "/gmi,'"
	$string9 = "<font></font><body id"
	$string10 = " epjtjqe; fqczi > 0; fqczi--){for (bwjmgl7 "
	$string11 = "nbte)bb(egs%A%%A%%A%%A%%m"
	$string12 = "fvC9614165,,,1,1801151030,,0,,487641114,,1,141,914810036,,888,201te.)'etdc:ysaA%%A%%A%%A%%5sao,61,0,"
	$string13 = "(tiAmrd{/tnA%%A%%A%%A%%Aiin11,,1637,34191,626958314,11007,,61145,411,7,9,1821,,43,8311,26;d'ebt.dyvs"
	$string14 = "A%%A%%A%%Ao"
	$string15 = "hrksywd(cpkwisk4);/"
	$string16 = ";</script>"
condition:
	16 of them
}
