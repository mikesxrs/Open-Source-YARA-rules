rule angler_flash
{
meta:
	author = "Josh Berry"
	date = "2016-06-26"
	description = "Angler Exploit Kit Detection"
	hash0 = "8081397c30b53119716c374dd58fc653"
	sample_filetype = "unknown"
	yaragenerator = "https://github.com/Xen0ph0n/YaraGenerator"
strings:
	$string0 = "(9OOSp"
	$string1 = "r$g@ 0'[A"
	$string2 = ";R-1qTP"
	$string3 = "xwBtR4"
	$string4 = "YbVjxp"
	$string5 = "ddgXkF"
	$string6 = ")n'URF"
	$string7 = "vAzq@W"
	$string8 = "rOkX$6m<"
	$string9 = "@@DB}q "
	$string10 = "TiKV'iV"
	$string11 = "538x;B"
	$string12 = "9pEM{d"
	$string13 = ".SIy/O"
	$string14 = "ER<Gu,"
condition:
	14 of them
}
