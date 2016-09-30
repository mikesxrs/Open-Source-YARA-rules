rule blackhole1_jar
{
meta:
	author = "Josh Berry"
	date = "2016-06-26"
	description = "BlackHole1 Exploit Kit Detection"
	hash0 = "724acccdcf01cf2323aa095e6ce59cae"
	sample_filetype = "unknown"
	yaragenerator = "https://github.com/Xen0ph0n/YaraGenerator"
strings:
	$string0 = "Created-By: 1.6.0_18 (Sun Microsystems Inc.)"
	$string1 = "workpack/decoder.classmQ]S"
	$string2 = "workpack/decoder.classPK"
	$string3 = "workpack/editor.classPK"
	$string4 = "xmleditor/GUI.classmO"
	$string5 = "xmleditor/GUI.classPK"
	$string6 = "xmleditor/peers.classPK"
	$string7 = "v(SiS]T"
	$string8 = ",R3TiV"
	$string9 = "META-INF/MANIFEST.MFPK"
	$string10 = "xmleditor/PK"
	$string11 = "Z[Og8o"
	$string12 = "workpack/PK"
condition:
	12 of them
}
