rule blackhole2_jar2
{
meta:
	author = "Josh Berry"
	date = "2016-06-27"
	description = "BlackHole2 Exploit Kit Detection"
	hash0 = "add1d01ba06d08818ff6880de2ee74e8"
	sample_filetype = "unknown"
	yaragenerator = "https://github.com/Xen0ph0n/YaraGenerator"
strings:
	$string0 = "6_O6d09"
	$string1 = "juqirvs.classPK"
	$string2 = "hw.classPK"
	$string3 = "a.classPK"
	$string4 = "w.classuS]w"
	$string5 = "w.classPK"
	$string6 = "YE}0vCZ"
	$string7 = "v)Q,Ff"
	$string8 = "%8H%t("
	$string9 = "hw.class"
	$string10 = "a.classmV"
	$string11 = "2CniYFU"
	$string12 = "juqirvs.class"
condition:
	12 of them
}
