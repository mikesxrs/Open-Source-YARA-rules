rule blackhole2_htm10
{
meta:
	author = "Josh Berry"
	date = "2016-06-27"
	description = "BlackHole2 Exploit Kit Detection"
	hash0 = "83704d531c9826727016fec285675eb1"
	hash1 = "103ef0314607d28b3c54cd07e954cb25"
	hash2 = "16c002dc45976caae259d7cabc95b2c3"
	hash3 = "fd84d695ac3f2ebfb98d3255b3a4e1de"
	hash4 = "c7b417a4d650c72efebc2c45eefbac2a"
	hash5 = "c3c35e465e316a71abccca296ff6cd22"
	hash2 = "16c002dc45976caae259d7cabc95b2c3"
	hash7 = "10ce7956266bfd98fe310d7568bfc9d0"
	hash8 = "60024caf40f4239d7e796916fb52dc8c"
	sample_filetype = "js-html"
	yaragenerator = "https://github.com/Xen0ph0n/YaraGenerator"
strings:
	$string0 = "</body></html>"
	$string1 = "/icons/back.gif"
	$string2 = ">373K</td><td>"
	$string3 = "/icons/unknown.gif"
	$string4 = ">Last modified</a></th><th><a href"
	$string5 = "tmp.gz"
	$string6 = ">tmp.gz</a></td><td align"
	$string7 = "nbsp;</td><td align"
	$string8 = "</table>"
	$string9 = ">  - </td><td>"
	$string10 = ">filefdc7aaf4a3</a></td><td align"
	$string11 = ">19-Sep-2012 07:06  </td><td align"
	$string12 = "><img src"
	$string13 = "file3fa7bdd7dc"
	$string14 = "  <title>Index of /files</title>"
	$string15 = "0da49e042d"
condition:
	15 of them
}
