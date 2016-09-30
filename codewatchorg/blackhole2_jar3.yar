rule blackhole2_jar3
{
meta:
	author = "Josh Berry"
	date = "2016-06-27"
	description = "BlackHole2 Exploit Kit Detection"
	hash0 = "c7abd2142f121bd64e55f145d4b860fa"
	sample_filetype = "unknown"
	yaragenerator = "https://github.com/Xen0ph0n/YaraGenerator"
strings:
	$string0 = "69/sj]]o"
	$string1 = "GJk5Nd"
	$string2 = "vcs.classu"
	$string3 = "T<EssB"
	$string4 = "1vmQmQ"
	$string5 = "Kf1Ewr"
	$string6 = "c$WuuuKKu5"
	$string7 = "m.classPK"
	$string8 = "chcyih.classPK"
	$string9 = "hw.class"
	$string10 = "f';;;;{"
	$string11 = "vcs.classPK"
	$string12 = "Vbhf_6"
condition:
	12 of them
}
