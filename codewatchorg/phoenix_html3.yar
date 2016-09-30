rule phoenix_html3
{
meta:
	author = "Josh Berry"
	date = "2016-06-26"
	description = "Phoenix Exploit Kit Detection"
	hash0 = "d7cacbff6438d866998fc8bfee18102d"
	sample_filetype = "js-html"
	yaragenerator = "https://github.com/Xen0ph0n/YaraGenerator"
strings:
	$string0 = "mtfla/,)asaf)'}"
	$string1 = "72267E7C'A3035CFC415DFAAA834B208D8C230FD303E2EFFE386BE05960C588C6E85650746E690C39F706F97DC74349BA134"
	$string2 = "N'eiui7F6e617e00F145A002645E527BFF264842F877B2FFC1FE84BCC6A50F0305B5B0C36A019F53674FD4D3736C494BD5C2"
	$string3 = "lndl}})<>"
	$string4 = "otodc};b<0:D>r5d4u%c005u%0028u%251eu%a095u%6028u%0028u%2500u%f7f7u%70d7u%2025u%9008u%08f8u%c607usu%3"
	$string5 = "tuJaboaopb"
	$string6 = "a(vxf{p'tSowa.i,1NIWm("
	$string7 = "2004et"
	$string8 = "2054sttE5356496478"
	$string9 = "yi%A%%A%%A%%A%Cvld3,5314,004,6211,931,,,011394617,983,1154,5,1,,1,1,13,08,4304,1"
	$string10 = "0ovel04ervEeieeem)h))B(ihsAE;u%04b8u%1c08u%0e50u%a000u%1010u%4000u%20afu%0006u%2478u%0020u%1065u%210"
	$string11 = "/gmi,String.fromCharCode(2"
	$string12 = "ncBcaocta.ye"
	$string13 = "0201010030004A033102090;na"
	$string14 = "66u%0(ec'h{iis%%A%%A%%A%%A%frS1,,8187,1,4,11,91516,,61,,10841,1,13,,,11248,01818849,23,,,,791meits0e"
	$string15 = "D11C0002C0069733E60656F6462070D000402DFF200696E"
	$string16 = "810p0y98"
	$string17 = "9,0,e'Fm692E583760"
	$string18 = "57784234633a)(u"
condition:
	18 of them
}
