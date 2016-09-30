rule phoenix_html5
{
meta:
	author = "Josh Berry"
	date = "2016-06-26"
	description = "Phoenix Exploit Kit Detection"
	hash0 = "30afdca94d301905819e00a7458f4a4e"
	sample_filetype = "js-html"
	yaragenerator = "https://github.com/Xen0ph0n/YaraGenerator"
strings:
	$string0 = "dtesu}"
	$string1 = "<textarea>function gvgsxoy(gwcqg1){return gwcqg1.replace(/"
	$string2 = "v}Ahnhxwet"
	$string3 = "0125C6BBA2B84F7A1D2940C04C8B7449A40EEB0D14C8003535C0042D75E05F0D7F3E0A7B4E33EB4D8D47119290FC"
	$string4 = "a2Fs2325223869e'Fm2873367130"
	$string5 = "m0000F0F6E66607C71646F6607000107FA61021F6060(aeWWIN"
	$string6 = ")(r>hd1/dNasmd(fpas"
	$string7 = "9,0,e'Fm692E583760"
	$string8 = "5ud(dis"
	$string9 = "nacmambuntcmi"
	$string10 = "Fa078597467,1C0e674366871,'2F"
	$string11 = "Fa56F386A76,180e828592024,'2F"
	$string12 = "alA)(2avoyOi;ic)t6])teptp,an}tnv0i'fms<uic"
	$string13 = "iR'nandee"
	$string14 = "('0.aEa-9leal"
	$string15 = "bsD0seF"
	$string16 = "t.ck263/6F3a001CE7A2684067F98BEC18B738801EF1F7F7E49A088695050C000865FC38080FE23727E0E8DE9CB53E748472"
condition:
	16 of them
}
