rule blackhole2_pdf
{
meta:
	author = "Josh Berry"
	date = "2016-06-27"
	description = "BlackHole2 Exploit Kit Detection"
	hash0 = "d1e2ff36a6c882b289d3b736d915a6cc"
	sample_filetype = "pdf"
	yaragenerator = "https://github.com/Xen0ph0n/YaraGenerator"
strings:
	$string0 = "/StructTreeRoot 5 0 R/Type/Catalog>>"
	$string1 = "0000036095 00000 n"
	$string2 = "http://www.xfa.org/schema/xfa-locale-set/2.1/"
	$string3 = "subform[0].ImageField1[0])/Subtype/Widget/TU(Image Field)/Parent 22 0 R/F 4/P 8 0 R/T<FEFF0049006D00"
	$string4 = "0000000026 65535 f"
	$string5 = "0000029039 00000 n"
	$string6 = "0000029693 00000 n"
	$string7 = "%PDF-1.6"
	$string8 = "27 0 obj<</Subtype/Type0/DescendantFonts 28 0 R/BaseFont/KLGNYZ"
	$string9 = "0000034423 00000 n"
	$string10 = "0000000010 65535 f"
	$string11 = ">stream"
	$string12 = "/Pages 2 0 R%/StructTreeRoot 5 0 R/Type/Catalog>>"
	$string13 = "19 0 obj<</Subtype/Type1C/Length 23094/Filter/FlateDecode>>stream"
	$string14 = "0000003653 00000 n"
	$string15 = "0000000023 65535 f"
	$string16 = "0000028250 00000 n"
	$string17 = "iceRGB>>>>/XStep 9.0/Type/Pattern/TilingType 2/YStep 9.0/BBox[0 0 9 9]>>stream"
	$string18 = "<</Root 1 0 R>>"
condition:
	18 of them
}
