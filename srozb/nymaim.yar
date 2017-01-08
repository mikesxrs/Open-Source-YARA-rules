/*
	Yara Rule Set
	Author: YarGen Rule Generator
	Date: 2016-11-14
	Identifier: nymaim
*/

/* Rule Set ----------------------------------------------------------------- */

rule debounce_9_exe {
	meta:
		description = "Auto-generated rule - file debounce-9.exe.malware"
		author = "YarGen Rule Generator"
		reference = "not set"
		date = "2016-11-14"
		hash1 = "d9322a22645db8abf5f49257aa0c2cbfd0b86e54f5fe18871989437f77cc7690"
	strings:
		$x1 = "X:\\6tk\\i67\\orl\\d8tiys3\\254isaz\\af7bs\\pvwgz\\0j3uf2s\\hk0q0q\\8h58eirc\\pu6cpbr\\wrn.pdb" fullword ascii /* score: '30.00' */
		$s2 = "}]vmP8=mP8=mP8=mP8=N3 \"L5#\"N:\"#L7%#;(" fullword ascii /* score: '16.03' */
		$s3 = " noqcn    o.exe" fullword wide /* score: '14.03' */
		$s4 = ":: :!:\":-:2:3:5:<:>:C:F:M:N:O:P:T:V:\\:]:_:d:h:r:s:x:{:" fullword ascii /* score: '14.00' */
		$s5 = "\\C.1\\C.1^A+5\\C.1U?.AU?.AU?.AU?.AR>-ER>-ER>-ER>-EN9)CN9)CN9)CN9)CB0 3D0!4D0!4A*#54#" fullword ascii /* score: '14.00' */
		$s6 = "\\C.1\\C.1\\C.1\\C.1U?.AU?.AV6*>VA+@R>-ER>-ER>-ESA*CN9)CN9)CN9)CN9)CC- 3D0!4D0!4D0!43#" fullword ascii /* score: '14.00' */
		$s7 = "I0x8c159c17" fullword wide /* base64 encoded string '#L|s^}s^' */ /* score: '14.00' */
		$s8 = "\\C.1\\C.1\\C.1\\C.1U?.AU?.AV>/AU?.AR>-ER>-EO:/ER>-EN9)CP6%AN9)CN9)CD0!4D0!4D0!4D0!42%" fullword ascii /* score: '14.00' */
		$s9 = "h\"q'u+HaL{$oYB8 -ZvwL>PoBpLv\\(fy).>?dSgD#1Rz3,$k<" fullword ascii /* score: '13.00' */
		$s10 = "\\9%I[:(cmdIiP<qj" fullword ascii /* score: '12.00' */
		$s11 = "jKuvV;[vV;[vV;[vV;[cF.GcF.GcF.GcF.GP6$3P6$3P6$3P6$3=)" fullword ascii /* score: '12.00' */
		$s12 = "oJwvV;[vV;[vV;[vV;[aF+IcF.GcF.GcF.GP6$3P6$3P6$3P6$3=)" fullword ascii /* score: '12.00' */
		$s13 = "jKuvV;[vV;[vV;[vV;[cF.GcF.GcF.GcJ0DP6$3P6$3O6#1P6$3=)" fullword ascii /* score: '12.00' */
		$s14 = "jKuvV;[vV;[vV;[vV;[cF.GcF.GcF.GjE,ER9#2P6$3P6$3P6$3=)" fullword ascii /* score: '12.00' */
		$s15 = "N:\\ZjD4W" fullword ascii /* score: '12.00' */
		$s16 = "u30b%-0+K.P3M)q+_<jS%RZNh%" fullword ascii /* score: '10.42' */
		$s17 = "4&414147494B4C4F4F4G4H4L4M4N4P4R4T4V4W4Y4[4\\4e4f4s4t4z4|4~4" fullword ascii /* score: '10.42' */
		$s18 = "9!9!9$9+9-9.9/909496989@9A9O9U9V9V9X9_9d9e9g9j9p9q9s9t9t9u9}9" fullword ascii /* score: '10.00' */
		$s19 = "wt!yKgetgM\\f3=" fullword ascii /* score: '9.42' */
		$s20 = "3 3\"3#3%3+3131373:3>3>3B3B3H3K3O3S3T3U3a3h3h3p3r3u3v3" fullword ascii /* score: '9.00' */
	condition:
		( uint16(0) == 0x5a4d and filesize < 2000KB and ( 1 of ($x*) and 5 of ($s*) ) ) or ( all of them )
}

rule glonass_65_exe {
	meta:
		description = "Auto-generated rule - file glonass-65.exe.malware"
		author = "YarGen Rule Generator"
		reference = "not set"
		date = "2016-11-14"
		hash1 = "25bbdc3712725db0a0845e74b36c5df287d7912533c58dfe866f3f3bfe55c7b7"
	strings:
		$s1 = "C:\\cr08pn8j\\z\\sfnpn\\s2g9i3k\\9tn\\l\\mame\\1l0et\\9yetid9r\\79h.pdb" fullword ascii /* score: '25.00' */
		$s2 = "ClassicExplorerSettings.exe" fullword wide /* score: '20.00' */
		$s3 = "; ;\";2;8;<;?;C;C;I;O;U;Y;\\;];];_;d;f;h;k;n;q;u;y;z;" fullword ascii /* score: '9.17' */
		$s4 = "Q9Q.KUK" fullword ascii /* score: '9.00' */
		$s5 = "<)<*<,<-</</<2<2<9<F<M<M<O<T<V<Z<[<k<o<p<r<s<s<t<u<z<" fullword ascii /* score: '9.00' */
		$s6 = "> >\">0>1>1>6>8>=>=>B>E>H>T>V>\\>e>j>j>v>w>x>y>" fullword ascii /* score: '8.00' */
		$s7 = ": :):-:0:5:::F:G:G:X:Y:Z:]:d:d:h:h:l:n:n:u:" fullword ascii /* score: '8.00' */
		$s8 = "=#='=,=0=4=:=<===H=T=[=f=m=u=w=x=y=z={=|=}=" fullword ascii /* score: '8.00' */
		$s9 = "0xba%u%u%d" fullword wide /* score: '8.00' */
		$s10 = "t -qKu" fullword ascii /* score: '7.00' */
		$s11 = "]/`d -eh" fullword ascii /* score: '7.00' */
		$s12 = "hhhhee" fullword ascii /* score: '7.00' */
		$s13 = "ME -MM='" fullword ascii /* score: '7.00' */
		$s14 = "Copyright (C) 2009-2015, Ivo Beltchev" fullword wide /* score: '7.00' */
		$s15 = "[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[" fullword ascii /* score: '7.00' */
		$s16 = "JPHROE" fullword ascii /* score: '5.50' */
		$s17 = "$-- +kNNkkkkNNNN" fullword ascii /* score: '5.17' */
		$s18 = "\\\\0RD\"MLI  " fullword ascii /* score: '5.17' */
		$s19 = "[[[[[[[[[[[[[[[[[[" fullword ascii /* score: '5.00' */
		$s20 = "[[[[[[[[[[[[[[[[[[[[[[" fullword ascii /* score: '5.00' */
	condition:
		( uint16(0) == 0x5a4d and filesize < 2000KB and ( 10 of ($s*) ) ) or ( all of them )
}

/* Super Rules ------------------------------------------------------------- */

