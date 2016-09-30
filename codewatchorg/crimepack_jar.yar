rule crimepack_jar
{
meta:
	author = "Josh Berry"
	date = "2016-06-26"
	description = "CrimePack Exploit Kit Detection"
	hash0 = "d48e70d538225bc1807842ac13a8e188"
	sample_filetype = "unknown"
	yaragenerator = "https://github.com/Xen0ph0n/YaraGenerator"
strings:
	$string0 = "r.JM,IM"
	$string1 = "cpak/Crimepack$1.classPK"
	$string2 = "cpak/KAVS.classPK"
	$string3 = "cpak/KAVS.classmQ"
	$string4 = "cpak/Crimepack$1.classmP[O"
	$string5 = "META-INF/MANIFEST.MF"
	$string6 = "META-INF/MANIFEST.MFPK"
condition:
	6 of them
}
