rule blackhole2_jar
{
meta:
	author = "Josh Berry"
	date = "2016-06-27"
	description = "BlackHole2 Exploit Kit Detection"
	hash0 = "86946ec2d2031f2b456e804cac4ade6d"
	sample_filetype = "unknown"
	yaragenerator = "https://github.com/Xen0ph0n/YaraGenerator"
strings:
	$string0 = "k0/3;N"
	$string1 = "g:WlY0"
	$string2 = "(ww6Ou"
	$string3 = "SOUGX["
	$string4 = "7X2ANb"
	$string5 = "r8L<;zYH)"
	$string6 = "fbeatbea/fbeatbee.classPK"
	$string7 = "fbeatbea/fbeatbec.class"
	$string8 = "fbeatbea/fbeatbef.class"
	$string9 = "fbeatbea/fbeatbef.classPK"
	$string10 = "fbeatbea/fbeatbea.class"
	$string11 = "fbeatbea/fbeatbeb.classPK"
	$string12 = "nOJh-2"
	$string13 = "[af:Fr"
condition:
	13 of them
}
