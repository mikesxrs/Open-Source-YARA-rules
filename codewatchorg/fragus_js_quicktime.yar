rule fragus_js_quicktime
{
meta:
	author = "Josh Berry"
	date = "2016-06-26"
	description = "Fragus Exploit Kit Detection"
	hash0 = "6bfc7bb877e1a79be24bd9563c768ffd"
	sample_filetype = "js-html"
	yaragenerator = "https://github.com/Xen0ph0n/YaraGenerator"
strings:
	$string0 = "                setTimeout("
	$string1 = "wnd.location"
	$string2 = "window;"
	$string3 = "        var pls "
	$string4 = "        mem_flag "
	$string5 = ", 1500);} else{ PRyyt4O3wvgz(1);}"
	$string6 = "         } catch(e) { }"
	$string7 = " mem_flag) JP7RXLyEu();"
	$string8 = " 0x400000;"
	$string9 = "----------------------------------------------------------------------------------------------------"
	$string10 = "        heapBlocks "
	$string11 = "        return mm;"
	$string12 = "0x38);"
	$string13 = "        h();"
	$string14 = " getb(b,bSize);"
	$string15 = "getfile.php"
condition:
	15 of them
}
