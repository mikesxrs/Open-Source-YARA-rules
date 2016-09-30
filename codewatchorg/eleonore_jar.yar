rule eleonore_jar
{
meta:
	author = "Josh Berry"
	date = "2016-06-26"
	description = "Eleonore Exploit Kit Detection"
	hash0 = "ad829f4315edf9c2611509f3720635d2"
	sample_filetype = "unknown"
	yaragenerator = "https://github.com/Xen0ph0n/YaraGenerator"
strings:
	$string0 = "r.JM,IM"
	$string1 = "dev/s/DyesyasZ.classPK"
	$string2 = "k4kjRv"
	$string3 = "dev/s/LoaderX.class}V[t"
	$string4 = "dev/s/PK"
	$string5 = "Hsz6%y"
	$string6 = "META-INF/MANIFEST.MF"
	$string7 = "dev/PK"
	$string8 = "dev/s/AdgredY.class"
	$string9 = "dev/s/DyesyasZ.class"
	$string10 = "dev/s/LoaderX.classPK"
	$string11 = "eS0L5d"
	$string12 = "8E{4ON"
condition:
	12 of them
}
