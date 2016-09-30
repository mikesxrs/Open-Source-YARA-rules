rule phoenix_html11
{
meta:
	author = "Josh Berry"
	date = "2016-06-26"
	description = "Phoenix Exploit Kit Detection"
	hash0 = "be8c81288f9650e205ed13f3167ce256"
	sample_filetype = "js-html"
	yaragenerator = "https://github.com/Xen0ph0n/YaraGenerator"
strings:
	$string0 = "D'0009F0C6941617C43427A76080001000F47020C606volv99,0,6,"
	$string1 = "';)nWd"
	$string2 = "IW'eeCn)s.a9e;0CF300FF379011078E047873754163636960496270486264416455747D69737812060209011301010104D0"
	$string3 = "D8D51F5100019006D60667F2E056940170E01010747"
	$string4 = "515F2F436WemBh2A4560683aFanoi(utse.o1/f;pistelzi"
	$string5 = "/p(e/oah)FHw'aaarDsnwi-"
	$string6 = "COa506u%db10u%1057u%f850u%f500u%0683u%05a8u%0030u%0706u%d300u%585du%38d0u%0080u%5612u'u%A2DdF6u%1M:."
	$string7 = "S(yt)Dj"
	$string8 = "FaA26285325,150e8292A6968,'2F"
	$string9 = "0200e{b<0:D>r5d4u%c005u%0028u%251eu%a095u%6028u%0028u%2500u%f7f7u%70d7u%2025u%9008u%08f8u%c607usu%37"
	$string10 = "(mEtlltopo{{e"
	$string11 = "aSmd'lm/t/im.}d.-Ljg,l-"
	$string12 = "r)C4snfapfuo}"
	$string13 = "').replace(/"
	$string14 = "A282A5ifA160F2628206(a"
	$string15 = "obn0cf"
	$string16 = "d(i'C)rtr.'pvif)iv1ilW)S((Ltl.)2,0,9;0se"
	$string17 = "E23s3003476B18703C179396D08B841BC554F11678F0FEB9505FB355E044F33A540F61743738327E32D97D070FA37D87s000"
	$string18 = "603742E545904575'294E20680,6F902E292A60''E6202A4E6468},e))tep"
condition:
	18 of them
}
