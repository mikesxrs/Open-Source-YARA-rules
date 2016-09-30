rule phoenix_jar2
{
meta:
	author = "Josh Berry"
	date = "2016-06-26"
	description = "Phoenix Exploit Kit Detection"
	hash0 = "989c5b5eaddf48010e62343d7a4db6f4"
	sample_filetype = "unknown"
	yaragenerator = "https://github.com/Xen0ph0n/YaraGenerator"
strings:
	$string0 = "a66d578f084.classeQ"
	$string1 = "a4cb9b1a8a5.class"
	$string2 = ")szNu\\MutK"
	$string3 = "qCCwBU"
	$string4 = "META-INF/MANIFEST.MF"
	$string5 = "QR,GOX"
	$string6 = "ab5601d4848.classmT"
	$string7 = "a6a7a760c0e["
	$string8 = "2ZUK[L"
	$string9 = "2VT(Au5"
	$string10 = "a6a7a760c0ePK"
	$string11 = "aa79d1019d8.class"
	$string12 = "aa79d1019d8.classPK"
	$string13 = "META-INF/MANIFEST.MFPK"
	$string14 = "ab5601d4848.classPK"
condition:
	14 of them
}
