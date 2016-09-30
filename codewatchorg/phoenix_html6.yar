rule phoenix_html6
{
meta:
	author = "Josh Berry"
	date = "2016-06-26"
	description = "Phoenix Exploit Kit Detection"
	hash0 = "4aabb710cf04240d26c13dd2b0ccd6cc"
	sample_filetype = "js-html"
	yaragenerator = "https://github.com/Xen0ph0n/YaraGenerator"
strings:
	$string0 = "F4B6B2E67)A780A373A633;ast2316363677fa'es6F3635244"
	$string1 = "piia.a}rneecc.cnuoir"
	$string2 = "0448D5A54BE10A5DA628100AC3F3D53C9CAEBFF7E1E805080B044057CB1C0EF7F263DC64E0CBE47C2A21E55E9EA620000106"
	$string3 = "],enEn..o"
	$string4 = "o;1()sna"
	$string5 = "(eres(0.,"
	$string6 = "}fs2he}o.t"
	$string7 = "f'u>jisch3;)Ie)C'eO"
	$string8 = "refhiacei"
	$string9 = "0026632528(sCE7A2684067F98BEC1s00000F512Fm286631666"
	$string10 = "vev%80b4u%ee18u%28b8u%2617u%5c08u%0e50u%a000u%9006u%76efu%b1cbu%ba2fu%6850u%0524u%9720u%f70<}1msa950"
	$string11 = "pdu,xziien,ie"
	$string12 = "rr)l;.)vr.nbl"
	$string13 = "ii)ruccs)1e"
	$string14 = "F30476737930anD<tAhnhxwet"
	$string15 = ")yf{(ee..erneef"
	$string16 = "ieiiXuMkCSwetEet"
	$string17 = "F308477E7A7itme"
condition:
	17 of them
}
