rule fragus_js_flash
{
meta:
	author = "Josh Berry"
	date = "2016-06-26"
	description = "Fragus Exploit Kit Detection"
	hash0 = "377431417b34de8592afecaea9aab95d"
	sample_filetype = "js-html"
	yaragenerator = "https://github.com/Xen0ph0n/YaraGenerator"
strings:
	$string0 = "document.appendChild(bdy);try{for (i"
	$string1 = "0; i<10; i"
	$string2 = "default"
	$string3 = "var m "
	$string4 = "/g, document.getElementById('divid').innerHTML));"
	$string5 = " n.substring(0,r/2);"
	$string6 = "document.getElementById('f').innerHTML"
	$string7 = "'atk' onclick"
	$string8 = "function MAKEHEAP()"
	$string9 = "document.createElement('div');"
	$string10 = "<button id"
	$string11 = "/g, document.getElementById('divid').innerHTML);"
	$string12 = "document.body.appendChild(gg);"
	$string13 = "var bdy "
	$string14 = "var gg"
	$string15 = " unescape(gg);while(n.length<r/2) { n"
condition:
	15 of them
}
