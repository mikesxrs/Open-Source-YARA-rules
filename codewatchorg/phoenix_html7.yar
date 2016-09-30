rule phoenix_html7
{
meta:
	author = "Josh Berry"
	date = "2016-06-26"
	description = "Phoenix Exploit Kit Detection"
	hash0 = "f0e1b391ec3ce515fd617648bec11681"
	sample_filetype = "js-html"
	yaragenerator = "https://github.com/Xen0ph0n/YaraGenerator"
strings:
	$string0 = "EBF0a0001B05D266503046C7A491A0C00044F0002035D0D0twl''WIN"
	$string1 = "ah80672528657"
	$string2 = "n);tctt)Eltc(Dj"
	$string3 = ";cnt2<tEf"
	$string4 = "iwkne){bvfvgzg5"
	$string5 = "..'an{ea-Ect'8-huJ.)/l'/tCaaa}<Ct95l"
	$string6 = "'WIWhaFtF662F6577IseFe427347637"
	$string7 = "ddTh75e{"
	$string8 = "Ae'n,,9"
	$string9 = "%E7E3Vemtyi"
	$string10 = "cf'treran"
	$string11 = "ncBcaocta.ye"
	$string12 = ")'0,p8k"
	$string13 = "0;{tc4F}c;eptdpduoCuuedPl80evD"
	$string14 = "iq,q,Nd(nccfr'Bearc'nBtpw"
	$string15 = ";)npeits0e.uvhF$I'"
	$string16 = "nvasai0.-"
	$string17 = "lmzv'is'"
condition:
	17 of them
}
