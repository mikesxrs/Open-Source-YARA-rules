rule blackhole2_htm6
{
meta:
	author = "Josh Berry"
	date = "2016-06-27"
	description = "BlackHole2 Exploit Kit Detection"
	hash0 = "a5f94d7bdeb88b57be67132473e48286"
	hash1 = "2e72a317d07aa1603f8d138787a2c582"
	hash2 = "9440d49e1ed0794c90547758ef6023f7"
	hash3 = "58265fc893ed5a001e3a7c925441298c"
	hash2 = "9440d49e1ed0794c90547758ef6023f7"
	hash0 = "a5f94d7bdeb88b57be67132473e48286"
	hash2 = "9440d49e1ed0794c90547758ef6023f7"
	hash7 = "95c6462d0f21181c5003e2a74c8d3529"
	hash8 = "9236e7f96207253b4684f3497bcd2b3d"
	sample_filetype = "js-html"
	yaragenerator = "https://github.com/Xen0ph0n/YaraGenerator"
strings:
	$string0 = "uniq1.png"
	$string1 = "edit.png"
	$string2 = "left.gif"
	$string3 = "infin.png"
	$string4 = "outdent.gif"
	$string5 = "exploit.gif"
	$string6 = "sem_g.png"
	$string7 = "Index of /library/templates/img"
	$string8 = "uniq1.png"
condition:
	8 of them
}
