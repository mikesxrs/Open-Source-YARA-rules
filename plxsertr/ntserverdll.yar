rule StormNtServerDLL : ntserverdll
{
meta:
	author = "plxsert"
	date = "2014-02-04"
	description = "Storm ntserver dll"
	sample_filetype = "dll"
	
strings:

	$string0 = "GET ^&&%$%$^%$#^&**(*((&*^%$##$%^&*(*&^%$%^&*.htmGET ^*%%RTG*(&^%FTGYHJIJ%^&*()*&*^&%RDFG(JKJH.aspGET *(&*^TGH*JIHG^&*(&^%*(*)OK)(*&^%$EDRGF%&^.htmlGET ^&&%$%$^%$#^&**(*((&*^%$##$%^&*(*&^%$%^&*.htmGET ^*%%RTG*(&^%FTGYHJIJ%^&*()*&*^&%RDFG(JKJH.aspGET *(&*^TGH*JIHG^&*(&^%*(*)OK)(*&^%$EDRGF%&^.html"
	$string1 = "Network China NetBot" fullword
	//$string2 = "Windows China Driver" fullword
	$string3 = "Made in China DDoS" fullword
	$string4 = "SerDLL.dll" fullword
	$string5 = "Accept-Language: zh-cn" fullword
	$string6 = "dddd  asdfddddf" fullword


condition:
	all of ($string*)
}