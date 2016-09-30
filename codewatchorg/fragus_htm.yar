rule fragus_htm
{
meta:
	author = "Josh Berry"
	date = "2016-06-26"
	description = "Fragus Exploit Kit Detection"
	hash0 = "f76deec07a61b4276acc22beef41ea47"
	sample_filetype = "js-html"
	yaragenerator = "https://github.com/Xen0ph0n/YaraGenerator"
strings:
	$string0 = ">Hello, "
	$string1 = "http://www.clantemplates.com"
	$string2 = "this template was created by Bl1nk and is downloadable at <B>ClanTemplates.com<BR></B>Replace "
	$string3 = "></TD></TR></TABLE> "
	$string4 = "Image21"
	$string5 = "scrollbar etc.<BR><BR>Enjoy, Bl1nk</FONT></TD></TR></TABLE><BR></CENTER></TD></TR> "
	$string6 = "to this WarCraft Template"
	$string7 = " document.getElementById) x"
	$string8 = "    if (a[i].indexOf("
	$string9 = "x.oSrc;"
	$string10 = "x.src; x.src"
	$string11 = "<HTML>"
	$string12 = "FFFFFF"
	$string13 = " CELLSPACING"
	$string14 = "images/layoutnormal_03.gif"
	$string15 = "<TR> <TD "
	$string16 = " CELLPADDING"
condition:
	16 of them
}
