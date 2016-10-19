

rule Trojan_Lurker2_ORION
{
	meta:
		Author = "HB"
		Date = "30 Sep 2013"
		Project = "Orion"
		Filename = "ntmrsvc.dll"
		Reference = "https://blogs.rsa.com/wp-content/uploads/2015/05/RSA-IR-Case-Study.pdf"

	strings:
		$b1 = {636D642E657865004C55524B}
		$b2 = {45525F52414353004C55524B25735F534D5F2573}
		$b3 = {4C55524B4552524143535F524D5F2573}
		$a1 = "01234567890123456789eric0123456789012345678karen"

	condition:
		any of them
}


rule Trojan_HIKIT
{
	meta:
		Author = "HB"
		Date = "26 Sep 2013"
		Project = "Orion"
		MD5 = "7D4F241428A2496142DF1C4A376CEC88"
		MD5 = "A5F07E00D3EEF7A16ECFEC03E94677E3"
		Reference = "https://blogs.rsa.com/wp-content/uploads/2015/05/RSA-IR-Case-Study.pdf"

	strings:
		$b1 = {63006F006E006E006500630074002000250064002E00250064002E00250064002E002500640020002500640000000000680069006B00690074003E}
		$b2 = {68006900740078002E0073007900730000006D00610074007200690078005F00700061007300730077006F007200}
		$b3 = {700072006F0078007900000063006F006E006E006500630074000000660069006C006500000000007300680065006C006C}
		$a1 = "Open backdoor error" wide
		$a2 = "data send err..." wide

	condition:
		any of ($b*) or all of ($a*)
}

rule Trojan_Derusbi {
        meta:
                Author = "RSA_IR"
                Date     = "4Sept13"
                File     = "derusbi_variants v 1.3"
                MD5      = " c0d4c5b669cc5b51862db37e972d31ec "
                Reference = "https://www.emc.com/collateral/white-papers/h12756-wp-shell-crew.pdf"
            strings:
        $b1 = {8b 15 ?? ?? ?? ?? 8b ce d3 ea 83 c6 ?? 30 90 ?? ?? ?? ??
40 3b 05 ?? ?? ?? ?? 72 ??}
        $b2 = {F3 5D 88 2E ?? ?? 00 00 BE 07 18 2E F0 5D 88 2E F7 5D 88 2E 0C A2 88 2E 4B 5D 88 2E F3 5D 88 2E}
        $b3 = {4E E6 40 BB}
        $b4 = {B1 19 BF 44}
        
        $b5 = {6A F5 44 3D ?? ?? 00 00 27 AF D4 3D 69 F5 44 3D 6E F5 44 3D 95 0A 44 3D D2 F5 44 3D 6A F5 44 3D}
        $b6 = {F3 5D 88 2E ?? ?? 00 00 BE 07 18 2E F0 5D 88 2E}
        $b7 = {D6 D5 A4 A3 ?? ?? 00 00 9B 8F 34 A3 D5 D5 A4 A3 D2 D5 A4
A3 29 2A A4 A3}
        $b8 = {C3 76 33 9F ?? ?? 00 00 8E 2C A3 9F C0 76 33 9F C7 76 33 9F 3C 89 33 9F}
 
    condition:
        2 of ($b1, $b2, $b3, $b4) and 1 of ($b5, $b6, $b7, $b8) }

rule Trojan_Derusbi_AP32_Orion
{
	meta:
		Author = "HB"
		Date = "30 Sep 2013"
		Project = "Orion"
		Info = "Compressed with aPACK"
        MagicBytes = "AP32" 
		Reference = "https://blogs.rsa.com/wp-content/uploads/2015/05/RSA-IR-Case-Study.pdf"

	strings:

		$http1 = {00000000485454502F312E312032303000000000485454502F312E3020323030}
		$http2 = {00000000434F4E4E4543542025733A256420485454502F312E300D0A0D0A0000}
		$file1 = "%s\\seclogon.nls"
		$file2 = "%s\\seclogon.nt"
		$file3 = "%swindows.exe"
		$o1	= "\\wsedrf\\qazxsw"
		$o2 = "\\shell\\open\\command"
		$b1 = {4C4F47494E494E464F3A2025640A0000}
		$b2 = {436F6465506167653A2025730A000000}
		$b3 = {5C636D642E657865}

	condition:
		all of ($http*) or all of ($file*) or all of ($o*) or all of ($b*)

}

rule Artifact_ORION_aPlib
{
	meta:
		Author = "HB"
		Date = "30 Sep 2013"
		Project = "Orion"
		Reference = "https://blogs.rsa.com/wp-content/uploads/2015/05/RSA-IR-Case-Study.pdf"
	strings:
		$a1 = "aPLib v"
		$a2 = "the smaller the better :)"
		$a3 = "Joergen Ibsen"
	condition:
		all of them

}

rule TROJAN_Notepad {
        meta:
                Author = "RSA_IR"
                Date     = "4Jun13"
                File     = "notepad.exe v 1.1"
                MD5      = "106E63DBDA3A76BEEB53A8BBD8F98927"
                Reference = "https://www.emc.com/collateral/white-papers/h12756-wp-shell-crew.pdf"
        strings:
                $s1 = "75BAA77C842BE168B0F66C42C7885997"
                $s2 = "B523F63566F407F3834BCC54AAA32524"
        condition:
                $s1 or $s2
}

rule liudoor{
meta:
        author = "RSA FirstWatch"
        date = "2015-07-23"
        description = "Detects Liudoor daemon backdoor"
        reference = "https://blogs.rsa.com/terracotta-vpn-enabler-of-advanced-threat-anonymity/"
        hash0 = "78b56bc3edbee3a425c96738760ee406"
        hash1 = "5aa0510f6f1b0e48f0303b9a4bfc641e"
        hash2 = "531d30c8ee27d62e6fbe855299d0e7de"
        hash3 = "2be2ac65fd97ccc97027184f0310f2f3"
		hash4 = "6093505c7f7ec25b1934d3657649ef07"
        type = "Win32 DLL"

strings:
        $string0 = "Succ"
        $string1 = "Fail"
        $string2 = "pass"
        $string3 = "exit"
        $string4 = "svchostdllserver.dll"
        $string5 = "L$,PQR"
        $string6 = "0/0B0H0Q0W0k0"
        $string7 = "QSUVWh"
        $string8 = "Ht Hu["
condition:
        all of them
}