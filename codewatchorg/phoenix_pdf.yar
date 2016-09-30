rule phoenix_pdf
{
meta:
	author = "Josh Berry"
	date = "2016-06-26"
	description = "Phoenix Exploit Kit Detection"
	hash0 = "16de68e66cab08d642a669bf377368da"
	hash1 = "bab281fe0cf3a16a396550b15d9167d5"
	sample_filetype = "pdf"
	yaragenerator = "https://github.com/Xen0ph0n/YaraGenerator"
strings:
	$string0 = "0000000254 00000 n"
	$string1 = "0000000295 00000 n"
	$string2 = "trailer<</Root 1 0 R /Size 7>>"
	$string3 = "0000000000 65535 f"
	$string4 = "3 0 obj<</JavaScript 5 0 R >>endobj"
	$string5 = "0000000120 00000 n"
	$string6 = "%PDF-1.0"
	$string7 = "startxref"
	$string8 = "0000000068 00000 n"
	$string9 = "endobjxref"
	$string10 = ")6 0 R ]>>endobj"
	$string11 = "0000000010 00000 n"
condition:
	11 of them
}
