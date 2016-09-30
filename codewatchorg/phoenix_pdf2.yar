rule phoenix_pdf2
{
meta:
	author = "Josh Berry"
	date = "2016-06-26"
	description = "Phoenix Exploit Kit Detection"
	hash0 = "33cb6c67f58609aa853e80f718ab106a"
	sample_filetype = "pdf"
	yaragenerator = "https://github.com/Xen0ph0n/YaraGenerator"
strings:
	$string0 = "\\nQb<%"
	$string1 = "0000000254 00000 n"
	$string2 = ":S3>v0$EF"
	$string3 = "trailer<</Root 1 0 R /Size 7>>"
	$string4 = "%PDF-1.0"
	$string5 = "0000000000 65535 f"
	$string6 = "endstream"
	$string7 = "0000000010 00000 n"
	$string8 = "6 0 obj<</JS 7 0 R/S/JavaScript>>endobj"
	$string9 = "3 0 obj<</JavaScript 5 0 R >>endobj"
	$string10 = "}pr2IE"
	$string11 = "0000000157 00000 n"
	$string12 = "1 0 obj<</Type/Catalog/Pages 2 0 R /Names 3 0 R >>endobj"
	$string13 = "5 0 obj<</Names[("
condition:
	13 of them
}
