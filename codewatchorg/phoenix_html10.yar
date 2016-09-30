rule phoenix_html10
{
meta:
	author = "Josh Berry"
	date = "2016-06-26"
	description = "Phoenix Exploit Kit Detection"
	hash0 = "f5f8dceca74a50076070f2593e82ec43"
	sample_filetype = "js-html"
	yaragenerator = "https://github.com/Xen0ph0n/YaraGenerator"
strings:
	$string0 = "pae>crAeahoilL"
	$string1 = "D11C0002C0069733E60656F6462070D000402DFF200696E"
	$string2 = "nbte)bbn"
	$string3 = "v9o16,0')0B80002328203;)82F00223A216ifA160A262A462(a"
	$string4 = "0442DFD2E30EC80E42D2E00AC3F3D53C9CAEBFF7E1E805080B044057CB1C0EF7F263DC64E0CBE47C2A21E370EE4A"
	$string5 = ";)npeits0e.uvr;][tvr"
	$string6 = "433EBE90242003E00C606D04036563435805000102000v020E656wa.i118,0',9F902F282620''C62022646660}{A780232A"
	$string7 = "350;var ysjzyq"
	$string8 = "aSmd'lm/t/im.}d.-Ljg,l-"
	$string9 = "0017687F6164706E6967060002008101'2176045ckb"
	$string10 = "63(dcma)nenn869"
	$string11 = "').replace(/"
	$string12 = "xd'c0lrls09sare"
	$string13 = "(]t.(7u(<p"
	$string14 = "d{et;bdBcriYtc:eayF20'F62;23C4AABA3B84FE21C2B0B066C0038B8353AF5C0B4DF8FF43E85FB6F05CEC4080236F3CDE6E"
	$string15 = "/var another;</textarea>"
	$string16 = "Fa527496C62eShHmar(bA,pPec"
	$string17 = "FaA244A676C,150e62A5B2B61,'2F"
condition:
	17 of them
}
