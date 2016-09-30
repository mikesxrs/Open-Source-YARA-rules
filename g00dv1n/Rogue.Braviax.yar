rule RogueBraviaxSampleA
{
    meta:
        Description = "Rogue.Braviax.sm"
        ThreatLevel = "5"

    strings:
		$ = "background_gradient_red.jpg" ascii wide
		$ = "red_shield_48.png" ascii wide
		$ = "pagerror.gif" ascii wide
		$ = "green_shield.png" ascii wide
		$ = "refresh.gif" ascii wide
		$ = "red_shield.png" ascii wide
		$ = "avp:scan" ascii wide
		$ = "avp:site" ascii wide
		$str1 = "Trojan-BNK.Win32.Keylogger.gen" ascii wide
		$str2 = "Trojan-PSW.Win32.Coced.219" ascii wide
		$str3 = "Email-Worm.Win32.Eyeveg.f" ascii wide
		$str4 = "Virus.BAT.Batalia1.840" ascii wide
		$str5 = "Trojan-SMS.SymbOS.Viver.a" ascii wide
		$str6 = "Trojan-Spy.HTML.Bankfraud.jk" ascii wide
		$str7 = "glohhstt7.com" ascii wide
		//$str8 = "Zorton" ascii wide
		//$str9 = "Rango" ascii wide
		//$str10 = "Sirius" ascii wide
		//$str11 = "A-Secure" ascii wide
		$str12 = "%1 Protection 201" ascii wide
		$str13 = "%1 Antivirus 201" ascii wide
		$str14 = "siriuc2014.com" ascii wide
		$str15 = "siriucs2016.com" ascii wide
		$str16 = "zorton2016.com" ascii wide
		$str17 = "zorton2015.com" ascii wide
		$str18 = "stormo10.com" ascii wide
		$str19 = "fscurat20.com" ascii wide
		$str20 = "fscurat21.com" ascii wide

    condition:
        (3 of them) or (any of ($str*))
}