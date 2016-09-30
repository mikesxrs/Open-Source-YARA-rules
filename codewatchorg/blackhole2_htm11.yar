rule blackhole2_htm11
{
meta:
	author = "Josh Berry"
	date = "2016-06-27"
	description = "BlackHole2 Exploit Kit Detection"
	hash0 = "e89b56df597688c489f06a0a6dd9efed"
	hash1 = "06ba331ac5ae3cd1986c82cb1098029e"
	hash2 = "a899dedb50ad81d9dbba660747828c7b"
	hash3 = "7cbb58412554327fe8b643204a046e2b"
	hash2 = "a899dedb50ad81d9dbba660747828c7b"
	hash0 = "e89b56df597688c489f06a0a6dd9efed"
	hash2 = "a899dedb50ad81d9dbba660747828c7b"
	hash7 = "530d31a0c45b79c1ee0c5c678e242c02"
	hash2 = "a899dedb50ad81d9dbba660747828c7b"
	sample_filetype = "js-html"
	yaragenerator = "https://github.com/Xen0ph0n/YaraGenerator"
strings:
	$string0 = "></th><th><a href"
	$string1 = "/icons/back.gif"
	$string2 = ">Description</a></th></tr><tr><th colspan"
	$string3 = "nbsp;</td><td align"
	$string4 = "nbsp;</td></tr>"
	$string5 = ">  - </td><td>"
	$string6 = "-//W3C//DTD HTML 3.2 Final//EN"
	$string7 = "<h1>Index of /dummy</h1>"
	$string8 = ">Size</a></th><th><a href"
	$string9 = " </head>"
	$string10 = "/icons/blank.gif"
	$string11 = "><hr></th></tr>"
condition:
	11 of them
}
