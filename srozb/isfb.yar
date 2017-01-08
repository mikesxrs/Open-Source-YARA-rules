/*
	Yara Rule Set
	Author: YarGen Rule Generator
	Date: 2016-11-14
	Identifier: 
*/

/* Rule Set ----------------------------------------------------------------- */

rule dimsmifs_exe {
	meta:
		description = "Auto-generated rule - file dimsmifs.exe.malware"
		author = "YarGen Rule Generator"
		reference = "not set"
		date = "2016-11-14"
		hash1 = "a6830427d8b818ac690af6f3a6fa974bc286d9e5861550279267280594284f5d"
	strings:
		$s1 = "G:\\DOCS!!!\\MyProg\\FREELANCE\\CURRENT\\Krypton\\Krypton_15.0\\Bin\\StubNew.pdb" fullword ascii /* score: '29.00' */
		$s2 = "LoaderPE: CreateProcess error:0x%X" fullword ascii /* score: '26.00' */
		$s3 = "zero.exe" fullword ascii /* score: '21.00' */
		$s4 = "RtlComputeCrc32=%d, PostCRC32=%d" fullword ascii /* score: '20.50' */
		$s5 = "GetProcAddressNt: %s - OK" fullword ascii /* score: '17.00' */
		$s6 = "FromBase64Crypto: PostCRC32 - OK" fullword ascii /* score: '16.00' */
		$s7 = "GetProcAddressNt#%d: %s: %s" fullword ascii /* score: '15.50' */
		$s8 = "LoaderPE: Error CRC GO Exit1" fullword ascii /* score: '14.00' */
		$s9 = "FromBase64Crypto: MemAllOk: %d, fun 0x%X" fullword ascii /* score: '13.50' */
		$s10 = "8\"x:\"5.)|z~</" fullword ascii /* score: '12.00' */
		$s11 = "DR0 = 0x%X,DR1 = 0x%X,DR2 = 0x%X,DR3 = 0x%X,DR6 = 0x%X,DR7 = 0x%X" fullword ascii /* score: '11.00' */
		$s12 = "FromBase64Crypto: B64 error = 0x%p" fullword ascii /* score: '10.00' */
		$s13 = "kgwnmqghbpfphjij" fullword ascii /* score: '9.00' */
		$s14 = "oxgxteijvinoawfpo" fullword ascii /* score: '9.00' */
		$s15 = "dwwKey from map = 0x%X" fullword ascii /* score: '8.00' */
		$s16 = "KEY = 0x%X, Len = %d" fullword ascii /* score: '8.00' */
		$s17 = "on_tls_callback2: Main FILE IS a DLL" fullword ascii /* score: '8.00' */
		$s18 = "blhvfpadnwxhseo" fullword ascii /* score: '8.00' */
		$s19 = "wtgtgbvdrclboj" fullword ascii /* score: '8.00' */
		$s20 = "wpjhgmtboviobx" fullword ascii /* score: '8.00' */
	condition:
		( uint16(0) == 0x5a4d and filesize < 700KB and ( 10 of ($s*) ) ) or ( all of them )
}

rule _tmp_vawtrak_14_3af {
	meta:
		description = "Auto-generated rule - file 14_3af.dat"
		author = "YarGen Rule Generator"
		reference = "not set"
		date = "2016-11-14"
		hash1 = "f57fd8a48e90a7c061ad9c783935a39a8e41b619fa86a3d5fcdb873635e9f970"
	strings:
		$s1 = "mpress.exe" fullword wide /* score: '22.00' */
		$s2 = "Z:\\fzw6rqq\\j\\gww\\tkclux\\8qt.pdb" fullword ascii /* score: '18.00' */
		$s3 = "PE32, PE32+, .NET Compressor" fullword wide /* score: '12.42' */
		$s4 = "Matcode comPRESSor" fullword wide /* score: '8.00' */
		$s5 = "Copyright (C) 2008, MATCODE Software" fullword wide /* score: '7.00' */
		$s6 = "* 8N'>" fullword ascii /* score: '7.00' */
		$s7 = "!Lyyyyyyyy+!" fullword ascii /* score: '7.00' */
		$s8 = "\\;.TuU" fullword ascii /* score: '7.00' */
		$s9 = "mpress" fullword wide /* score: '7.00' */
		$s10 = "o\"f&i\"Richg&i\"" fullword ascii /* score: '5.00' */
		$s11 = "qg&i\"g&i\"g&i\"9" fullword ascii /* score: '5.00' */
		$s12 = "m\"e&i\"g&i\"_&i\"g&h\"" fullword ascii /* score: '5.00' */
		$s13 = "MATCODE Software" fullword wide /* score: '5.00' */
	condition:
		( uint16(0) == 0x5a4d and filesize < 500KB and ( 10 of ($s*) ) ) or ( all of them )
}

rule FakturaVAT_6587_pdf_scr {
	meta:
		description = "Auto-generated rule - file FakturaVAT_6587.pdf.scr.txt"
		author = "YarGen Rule Generator"
		reference = "not set"
		date = "2016-11-14"
		hash1 = "031d175a52280e5da95a0265d7156ed67d63d5c9d79e4ea972586045e44dec11"
	strings:
		$s1 = "$$$$$$$$$$$$,,,,,,4444444<<<<<<DDDDDDDLLLLLLTTTTTT\\\\\\\\\\\\\\ddddddlllllltttttt||||||" fullword ascii /* score: '19.00' */
		$s2 = "$$$$$$$$$$$$,,,,,,,444444<<<<<<DDDDDDDLLLLLLTTTTLT\\\\\\\\\\\\dddddddlllllltttttt||||||" fullword ascii /* score: '18.00' */
		$s3 = "$$$$$$$$$$$$,,,,,,,444444<<<<<<DDDDDDDLLLLLLTTTTTT\\\\\\\\\\\\dddddddlllllltttttt||||||" fullword ascii /* score: '18.00' */
		$s4 = "$$$$$$$$$$$$,,,,,,4444444<<<<<<DDDDDDDLLLLLLTTTTLT\\\\\\\\\\\\dddddddlllllltttttt||||||" fullword ascii /* score: '18.00' */
		$s5 = "$$$$$$$$$$$$,,,,,,4444444<<<<<<DDDDDDDLLLLLLTTTTTT\\\\\\\\\\\\dddddddlllllltttttt||||||" fullword ascii /* score: '18.00' */
		$s6 = "$$$$$$$$$$$$,,,,,,4444444<<<<<<DDDDDDDLLLLLLTTTTLT\\\\\\\\T\\dddddddlllllltttttt||||||" fullword ascii /* score: '18.00' */
		$s7 = "$$$$$$$$$$$$,,,,,,4444444<<<<<<DDDDDDDLLLLLLTTTTTT\\\\\\\\T\\dddddddlllllltttttt||||||" fullword ascii /* score: '18.00' */
		$s8 = "$$$$$$$$$$$$,,,,,,4444444<<<<<<DDDDDDDLLLLLLTTTTLT\\\\\\\\T\\\\ddddddlllllltttttt||||||" fullword ascii /* score: '18.00' */
		$s9 = ".FTP()" fullword ascii /* score: '11.00' */
		$s10 = "L@CMainFrame" fullword ascii /* score: '7.00' */
		$s11 = "PAPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDI" ascii /* score: '6.50' */
		$s12 = "Laplacian" fullword wide /* score: '6.00' */
		$s13 = "Prewitt" fullword wide /* score: '5.00' */
		$s14 = "?????0-360??????" fullword wide /* score: '5.00' */
	condition:
		( uint16(0) == 0x5a4d and filesize < 500KB and ( 10 of ($s*) ) ) or ( all of them )
}

rule Sprawa_PL73092802_pdf {
	meta:
		description = "Auto-generated rule - file Sprawa_PL73092802.pdf.exe"
		author = "YarGen Rule Generator"
		reference = "not set"
		date = "2016-11-14"
		hash1 = "7f0359314eb3577075367df11699cafd8a5f6c36da0e58890acebbce4144eb05"
	strings:
		$s1 = "blOGk_" fullword ascii /* score: '8.00' */
		$s2 = "* lc~F" fullword ascii /* score: '7.00' */
		$s3 = ".jwK[ " fullword ascii /* score: '6.42' */
		$s4 = ".hvJ=R" fullword ascii /* score: '6.00' */
		$s5 = "K}i*%S4" fullword ascii /* score: '6.00' */
		$s6 = "1\"1'191C1H1d1n1" fullword ascii /* score: '5.00' */
		$s7 = "2\"3.373=3C3J3Q3n3" fullword ascii /* score: '5.00' */
		$s8 = "<l=+>,?<?M?U?e?v?" fullword ascii /* score: '5.00' */
		$s9 = "=*=2=P=X=#?>?O?o?" fullword ascii /* score: '5.00' */
		$s10 = "; ;$;(;,;0;4;l;t;|;" fullword ascii /* score: '5.00' */
		$s11 = ">#>)>5>;>D>J>_>e>p>|>" fullword ascii /* score: '5.00' */
		$s12 = "0)191?1K1Q1a1g1m1|1" fullword ascii /* score: '5.00' */
		$s13 = "<;<A<O<T<\\<b<p<u<}<" fullword ascii /* score: '5.00' */
		$s14 = "3&3/343:3D3M3X3d3i3y3~3" fullword ascii /* score: '5.00' */
		$s15 = "4080<0@0D0H0L0P0T0X0" fullword ascii /* score: '5.00' */
	condition:
		( uint16(0) == 0x5a4d and filesize < 700KB and ( 10 of ($s*) ) ) or ( all of them )
}

rule _tmp_vawtrak_14_3ae {
	meta:
		description = "Auto-generated rule - file 14_3ae.dat"
		author = "YarGen Rule Generator"
		reference = "not set"
		date = "2016-11-14"
		hash1 = "4153ff4da80c7ec5216cd65efde8766e7b448f70761ba26e45af902ed075f35b"
	strings:
		$s1 = "KERneL32.Dll" fullword ascii /* score: '23.00' */
		$s2 = "ystem32\\xpsp3res.dll" fullword wide /* score: '21.42' */
		$s3 = "http://www.bullguard.com0" fullword ascii /* score: '16.00' */
		$s4 = "'GlobalSign TSA for MS Authenticode - G20" fullword ascii /* score: '15.00' */
		$s5 = "attemperate" fullword ascii /* score: '15.00' */
		$s6 = "dsethead" fullword ascii /* score: '12.00' */
		$s7 = "horologe" fullword ascii /* score: '12.00' */
		$s8 = "~s:\\c@" fullword ascii /* score: '11.00' */
		$s9 = "supportless" fullword ascii /* score: '11.00' */
		$s10 = "eebhgfahigppdgqbgdieqigepp" fullword ascii /* score: '10.00' */
		$s11 = "cgaqgghcecfagpciapqpfgegpefdbb" fullword ascii /* score: '10.00' */
		$s12 = "microseismometrograph" fullword ascii /* score: '9.00' */
		$s13 = "acetmethylanilide" fullword ascii /* score: '9.00' */
		$s14 = "zygomaticoauricularis" fullword ascii /* score: '9.00' */
		$s15 = "sensorivasomotor" fullword ascii /* score: '9.00' */
		$s16 = "osteogenetic" fullword ascii /* score: '8.00' */
		$s17 = "extradural" fullword ascii /* score: '8.00' */
		$s18 = "advancing" fullword ascii /* score: '8.00' */
		$s19 = "motherliness" fullword ascii /* score: '8.00' */
		$s20 = "epicheirema" fullword ascii /* score: '8.00' */
	condition:
		( uint16(0) == 0x5a4d and filesize < 600KB and ( 10 of ($s*) ) ) or ( all of them )
}

/* Super Rules ------------------------------------------------------------- */

