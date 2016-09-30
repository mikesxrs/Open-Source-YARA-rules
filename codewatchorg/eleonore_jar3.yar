rule eleonore_jar3
{
meta:
	author = "Josh Berry"
	date = "2016-06-26"
	description = "Eleonore Exploit Kit Detection"
	hash0 = "f65f3b9b809ebf221e73502480ab6ea7"
	sample_filetype = "unknown"
	yaragenerator = "https://github.com/Xen0ph0n/YaraGenerator"
strings:
	$string0 = "16lNYF2V"
	$string1 = "META-INF/MANIFEST.MFPK"
	$string2 = "ghsdr/Jewredd.classPK"
	$string3 = "ghsdr/Gedsrdc.class"
	$string4 = "e[<n55"
	$string5 = "ghsdr/Gedsrdc.classPK"
	$string6 = "META-INF/"
	$string7 = "na}pyO"
	$string8 = "9A1.F\\"
	$string9 = "ghsdr/Kocer.class"
	$string10 = "MXGXO8"
	$string11 = "ghsdr/Kocer.classPK"
	$string12 = "ghsdr/Jewredd.class"
condition:
	12 of them
}
