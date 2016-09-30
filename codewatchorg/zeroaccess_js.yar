rule zeroaccess_js
{
meta:
	author = "Josh Berry"
	date = "2016-06-27"
	description = "ZeroAccess Exploit Kit Detection"
	hash0 = "a9f30483a197cfdc65b4a70b8eb738ab"
	sample_filetype = "js-html"
	yaragenerator = "https://github.com/Xen0ph0n/YaraGenerator"
strings:
	$string0 = "Square ad tag  (tile"
	$string1 = "  adRandNum "
	$string2 = " cellspacing"
	$string3 = "\\n//-->\\n</script>"
	$string4 = "format"
	$string5 = "//-->' "
	$string6 = "2287974446"
	$string7 = "NoScrBeg "
	$string8 = "-- start adblade -->' "
	$string9 = "3427054556"
	$string10 = "        while (i >"
	$string11 = "return '<table width"
	$string12 = "</scr' "
	$string13 = " s.substring(0, i"
	$string14 = " /></a></noscript>' "
	$string15 = "    else { isEmail "
	$string16 = ").submit();"
	$string17 = " border"
	$string18 = "pub-8301011321395982"
condition:
	18 of them
}
