rule phoenix_pdf3
{
meta:
	author = "Josh Berry"
	date = "2016-06-26"
	description = "Phoenix Exploit Kit Detection"
	hash0 = "bab281fe0cf3a16a396550b15d9167d5"
	sample_filetype = "pdf"
	yaragenerator = "https://github.com/Xen0ph0n/YaraGenerator"
strings:
	$string0 = "trailer<</Root 1 0 R /Size 7>>"
	$string1 = "stream"
	$string2 = ";_oI5z"
	$string3 = "0000000010 00000 n"
	$string4 = "3 0 obj<</JavaScript 5 0 R >>endobj"
	$string5 = "7 0 obj<</Filter[ /FlateDecode /ASCIIHexDecode /ASCII85Decode ]/Length 3324>>"
	$string6 = "endobjxref"
	$string7 = "L%}gE("
	$string8 = "0000000157 00000 n"
	$string9 = "1 0 obj<</Type/Catalog/Pages 2 0 R /Names 3 0 R >>endobj"
	$string10 = "0000000120 00000 n"
	$string11 = "4 0 obj<</Type/Page/Parent 2 0 R /Contents 12 0 R>>endobj"
condition:
	11 of them
}
