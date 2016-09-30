rule angler_flash_uncompressed
{
meta:
	author = "Josh Berry"
	date = "2016-06-26"
	description = "Angler Exploit Kit Detection"
	hash0 = "2543855d992b2f9a576f974c2630d851"
	sample_filetype = "unknown"
	yaragenerator = "https://github.com/Xen0ph0n/YaraGenerator"
strings:
	$string0 = "DisplayObjectContainer"
	$string1 = "Xtime2"
	$string2 = "(HMRTQ"
	$string3 = "flash.events:EventDispatcher$flash.display:DisplayObjectContainer"
	$string4 = "_e_-___-__"
	$string5 = "ZviJbf"
	$string6 = "random-"
	$string7 = "_e_-_-_-_"
	$string8 = "_e_------"
	$string9 = "817677162"
	$string10 = "_e_-__-"
	$string11 = "-[vNnZZ"
	$string12 = "5:unpad: Invalid padding value. expected ["
	$string13 = "writeByte/"
	$string14 = "enumerateFonts"
	$string15 = "_e_---___"
	$string16 = "_e_-_-"
	$string17 = "f(fOJ4"
condition:
	17 of them
}
