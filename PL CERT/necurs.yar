rule necurs
{
	meta:
		author="akrasuski1"
		reference = "https://www.cert.pl/en/news/single/necurs-hybrid-spam-botnet/"
	strings:
		$pushID0 = {68 0A CA 9B 2E}
		$pushID1 = {68 18 DD F0 3E}
		$pushID2 = {68 31 BF D7 B2}
		$pushID3 = {68 60 48 6A E1}
		$pushID4 = {68 84 9A 75 C3}
		$pushID5 = {68 9B 54 CC D8}
		$pushID6 = {68 EE A0 8A 0A}
		$pushID7 = {68 D7 91 35 54}
		$pushID8 = {68 44 FC 9D EA}
		$pushID9 = {68 A4 51 C4 74}

		$dga = {1B D9 01 7D 08 11 5D 0C	FF 45 FC 39 75 FC}
	
		$string_drivers = "%s\\drivers\\%s.sys"
		$string_findme = "findme"
		$string_stupid = "some stupid error" wide
		$string_bcdedit = "bcdedit.exe -set TESTSIGNING ON"

	condition:
		(2 of ($string*) and $dga)
		or
		($dga and 7 of ($pushID*))
		or
		(2 of ($string*) and 7 of ($pushID*))
}
