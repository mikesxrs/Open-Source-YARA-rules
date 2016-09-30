rule phoenix_html9
{
meta:
	author = "Josh Berry"
	date = "2016-06-26"
	description = "Phoenix Exploit Kit Detection"
	hash0 = "742d012b9df0c27ed6ccf3b234db20db"
	sample_filetype = "js-html"
	yaragenerator = "https://github.com/Xen0ph0n/YaraGenerator"
strings:
	$string0 = "tute)bbr:"
	$string1 = "nfho(tghRx"
	$string2 = "()irfE/Rt..cOcC"
	$string3 = "NcEnevbf"
	$string4 = "63FB8B4296BBC290A0.'0000079'Fh20216B6A6arA;<"
	$string5 = "wHe(cLnyeyet(a.i,r.{.."
	$string6 = "tute)bbdfiiix'bcr"
	$string7 = "itifdf)d1L2f'asau%d004u%8e00u%0419u%a58du%2093u%ec10u%0050u%00d4u%4622u%bcd1u%b1ceu%5000u%f7f5u%5606"
	$string8 = "2F4693529783'82F076676C38'te"
	$string9 = "sm(teoeoi)cfh))pihnipeeeo}.,(.(("
	$string10 = "ao)ntavlll{))ynlcoix}hiN.il'tes1ad)bm;"
	$string11 = "i)}m0f(eClei(/te"
	$string12 = "}aetsc"
	$string13 = "irefnig.pT"
	$string14 = "a0mrIif/tbne,(wsk,"
	$string15 = "500F14B06000000630E6B72636F60632C6E711C6E762E646F147F44767F650A0804061901020009006B120005A2006L"
	$string16 = ".hB.Csf)ddeSs"
	$string17 = "tnne,IPd4Le"
	$string18 = "hMdarc'nBtpw"
condition:
	18 of them
}
