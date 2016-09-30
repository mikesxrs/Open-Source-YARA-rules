rule phoenix_html
{
meta:
	author = "Josh Berry"
	date = "2016-06-26"
	description = "Phoenix Exploit Kit Detection"
	hash0 = "8395f08f1371eb7b2a2e131b92037f9a"
	sample_filetype = "js-html"
	yaragenerator = "https://github.com/Xen0ph0n/YaraGenerator"
strings:
	$string1 = "'></applet><body id"
	$string2 = "<applet mayscript"
	$string3 = "/gmi,String.fromCharCode(2"
	$string4 = "/gmi,' ').replace(/"
	$string5 = "pe;i;;.j1s->c"
	$string6 = "es4Det"
	$string7 = "<textarea>function"
        $string8 = ".replace(/"
	$string9 = ".jar' code"
	$string10 = ";iFc;ft'b)h{s"
condition:
	10 of them
}
