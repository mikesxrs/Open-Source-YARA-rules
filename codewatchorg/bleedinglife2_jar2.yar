rule bleedinglife2_jar2
{
meta:
	author = "Josh Berry"
	date = "2016-06-26"
	description = "BleedingLife2 Exploit Kit Detection"
	hash0 = "2bc0619f9a0c483f3fd6bce88148a7ab"
	sample_filetype = "unknown"
	yaragenerator = "https://github.com/Xen0ph0n/YaraGenerator"
strings:
	$string0 = "META-INF/MANIFEST.MFPK"
	$string1 = "RequiredJavaComponent.classPK"
	$string2 = "META-INF/JAVA.SFm"
	$string3 = "RequiredJavaComponent.class"
	$string4 = "META-INF/MANIFEST.MF"
	$string5 = "META-INF/JAVA.DSAPK"
	$string6 = "META-INF/JAVA.SFPK"
	$string7 = "5EVTwkx"
	$string8 = "META-INF/JAVA.DSA3hb"
	$string9 = "y\\Dw -"
condition:
	9 of them
}
