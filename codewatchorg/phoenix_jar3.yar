rule phoenix_jar3
{
meta:
	author = "Josh Berry"
	date = "2016-06-26"
	description = "Phoenix Exploit Kit Detection"
	hash0 = "c5655c496949f8071e41ea9ac011cab2"
	sample_filetype = "unknown"
	yaragenerator = "https://github.com/Xen0ph0n/YaraGenerator"
strings:
	$string0 = "'> >$>"
	$string1 = "bpac/PK"
	$string2 = "bpac/purok$1.classmP]K"
	$string3 = "bpac/KAVS.classmQ"
	$string4 = "'n n$n"
	$string5 = "bpac/purok$1.classPK"
	$string6 = "$.4aX,Gt<"
	$string7 = "bpac/KAVS.classPK"
	$string8 = "bpac/b.classPK"
	$string9 = "bpac/b.class"
condition:
	9 of them
}
