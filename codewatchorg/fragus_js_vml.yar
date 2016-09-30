rule fragus_js_vml
{
meta:
	author = "Josh Berry"
	date = "2016-06-26"
	description = "Fragus Exploit Kit Detection"
	hash0 = "8ab72337c815e0505fcfbc97686c3562"
	sample_filetype = "js-html"
	yaragenerator = "https://github.com/Xen0ph0n/YaraGenerator"
strings:
	$string0 = " 0x100000;"
	$string1 = "            var gg "
	$string2 = "/g, document.getElementById('divid').innerHTML));"
	$string3 = "                                var sss "
	$string4 = "                }"
	$string5 = "                        document.body.appendChild(obj);"
	$string6 = "                                var hbs "
	$string7 = " shcode; }"
	$string8 = " '<div id"
	$string9 = " hbs - (shcode.length"
	$string10 = "){ m[i] "
	$string11 = " unescape(gg);"
	$string12 = "                                var z "
	$string13 = "                                var hb "
	$string14 = " Math.ceil('0'"
condition:
	14 of them
}
