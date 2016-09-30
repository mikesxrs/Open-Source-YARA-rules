rule angler_flash2
{
meta:
	author = "Josh Berry"
	date = "2016-06-26"
	description = "Angler Exploit Kit Detection"
	hash0 = "23812c5a1d33c9ce61b0882f860d79d6"
	sample_filetype = "unknown"
	yaragenerator = "https://github.com/Xen0ph0n/YaraGenerator"
strings:
	$string0 = "4yOOUj"
	$string1 = "CSvI4e"
	$string2 = "'fwaEnkI"
	$string3 = "'y4m%X"
	$string4 = "eOc)a,"
	$string5 = "'0{Q5<"
	$string6 = "1BdX;P"
	$string7 = "D _J)C"
	$string8 = "-epZ.E"
	$string9 = "QpRkP."
	$string10 = "<o/]atel"
	$string11 = "@B.,X<"
	$string12 = "5r[c)U"
	$string13 = "52R7F'"
	$string14 = "NZ[FV'P"
condition:
	14 of them
}
