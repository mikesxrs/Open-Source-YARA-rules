rule zeroaccess_htm
{
meta:
	author = "Josh Berry"
	date = "2016-06-27"
	description = "ZeroAccess Exploit Kit Detection"
	hash0 = "0e7d72749b60c8f05d4ff40da7e0e937"
	sample_filetype = "js-html"
	yaragenerator = "https://github.com/Xen0ph0n/YaraGenerator"
strings:
	$string0 = "screen.height:"
	$string1 = "</script></head><body onload"
	$string2 = "Fx0ZAQRKXUVgbh0qNDRJVxYwGg4tGh8aHQoAVQQSNyo0NElXFjAaDi0NFQYESl1FBBNnTFoSPiBmADwnPTQxPSdKWUUEE2UcGR0z"
	$string3 = "0);-10<b"
	$string4 = "function fl(){var a"
	$string5 = "0);else if(navigator.mimeTypes"
	$string6 = ");b.href"
	$string7 = "/presults.jsp"
	$string8 = "128.164.107.221"
	$string9 = ")[0].clientWidth"
	$string10 = "presults.jsp"
	$string11 = ":escape(c),e"
	$string12 = "navigator.plugins.length)navigator.plugins["
	$string13 = "window;d"
	$string14 = "gr(),j"
	$string15 = "VIEWPORT"
	$string16 = "FQV2D0ZAH1VGDxgZVg9COwYCAwkcTzAcBxscBFoKAAMHUFVuWF5EVVYVdVtUR18bA1QdAU8HQjgeUFYeAEZ4SBEcEk1FTxsdUlVA"
condition:
	16 of them
}
