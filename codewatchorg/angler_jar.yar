rule angler_jar
{
meta:
	author = "Josh Berry"
	date = "2016-06-26"
	description = "Angler Exploit Kit Detection"
	hash0 = "3de78737b728811af38ea780de5f5ed7"
	sample_filetype = "unknown"
	yaragenerator = "https://github.com/Xen0ph0n/YaraGenerator"
strings:
	$string0 = "myftysbrth"
	$string1 = "classPK"
	$string2 = "8aoadN"
	$string3 = "j5/_<F"
	$string4 = "FXPreloader.class"
	$string5 = "V4w\\K,"
	$string6 = "W\\Vr2a"
	$string7 = "META-INF/MANIFEST.MF"
	$string8 = "Na8$NS"
	$string9 = "_YJjB'"
condition:
	9 of them
}