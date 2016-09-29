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


rule StormNtServerExe : ntserverexe
{
meta:
	author = "plxsert"
	date = "2014-01-15"
	description = "Storm ntserver payload"
	sample_filetype = "exe"
	
strings:
    $callWinExec = { 8B FA C1 E9 02 F3 A5 8B C8 83 E1 03 F3 A4 8D 4C 24 10 51 FF 15 48 50 40 00 }
    
	$string0 = "\\ntserver.dll" fullword
	$string1 = "iexplore.exe" fullword
	//$string2 = "C:\\Program Files\\Internet Explorer\\iexplore.exe" fullword
	$string3 = "SeDebugPrivilege" fullword


condition:
	all of ($string*) and ($callWinExec in (0..0x106c))
}


