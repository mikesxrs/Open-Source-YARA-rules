import "magic"

rule malrtf_cve_2012_0158 : exploit
{
	meta:
		author = "@h3x2b <tracker _AT h3x.eu>"
		description = "Detect weaponized RTF documents using cve_2012_0158"

	strings:
		//normal rtf beginning
		$rtf_format_00 = "{\\rtf1"
		//malformed rtf can have for example {\\rtA1
		$rtf_format_01 = "{\\rt"

		//MSComctlLib.ListViewCtrl.2
		$rtf_exploit_00 = "\\objclass MSComctlLib.ListViewCtrl.2" nocase
		$rtf_exploit_01 = "4D53436F6D63746C4C69622E4C697374566965774374726C2E32" nocase

		$rtf_exploit_02 = "\\objclass Package" nocase
		$rtf_exploit_03 = "5061636b61676500" nocase

		//False positives
		$fp_avast_win_01 = "algo.dll"
		$fp_avast_win_02 = "algo64.dll"
		$fp_avast_mac = "algo.so"

	condition:
		//new_file and
		//avoid false positives
		not (
			(magic.type() contains "PE" and any of ($fp_avast_win_*) ) or
			(magic.type() contains "Mach" and $fp_avast_mac )
		) and
		any of ($rtf_format_*) and
		any of ($rtf_exploit_*)

}


rule malrtf_pe_embedded : exploit
{
	meta:
		author = "@h3x2b <tracker _AT h3x.eu>"
		description = "Detect weaponized RTF documents with embedded executable"

	strings:
		//normal rtf beginning
		$rtf_format_00 = "{\\rtf1"
		//malformed rtf can have for example {\\rtA1
		$rtf_format_01 = "{\\rt"

		//Windows PE32 magic beginning - "MZ\x90"
		$rtf_payload_01 = "4D5A90" nocase

		//PE
		$rtf_payload_02 = "50450000"

		//String "!This"
		$rtf_payload_03 = "2154686973"

		//String "DOS mode"
		$rtf_payload_04 = "444f53206d6f6465" nocase

	condition:
		//new_file and
		any of ($rtf_format_*) and
		3 of ($rtf_payload_*)
}

rule malrtf_ole2link_cve_2017_0199 : exploit
{
	meta:
		author = "@h3x2b <tracker _AT h3x.eu>"
		description = "Detect weaponized RTF documents with OLE2Link exploit to URL Moniker HTA handling CVS-2017-0199"

	strings:
		//having \objautlink structure
		$rtf_olelink_01 = "\\objautlink" nocase wide ascii

		//having \objdata structure
		$rtf_olelink_02 = "\\objdata" nocase wide ascii

		//hex encoded OLE2Link
		$rtf_olelink_03 = "4f4c45324c696e6b" nocase wide ascii

		//hex encoded StdOleLink
		$rtf_olelink_04 = "5374644f6c654c696e6b" nocase wide ascii

		//hex encoded docfile magic - doc file albilae
		$rtf_olelink_05 = "d0cf11e0a1b11ae1" nocase wide ascii

                //GUID of URL Moniker
                $rtf_payload_01 = "e0c9ea79f9bace118c8200aa004ba90b" nocase wide ascii

		//hex encoded "http://"
		$rtf_payload_02 = "68007400740070003a002f002f00" nocase wide ascii

		//hex encoded "https://"
		$rtf_payload_03 = "680074007400700073003a002f002f00" nocase wide ascii

		//hex encoded "ftp://"
		$rtf_payload_04 = "6600740070003a002f002f00" nocase wide ascii


	condition:
		//new_file and
		//normal rtf header is {\rtf1, malformed rtf can have for example {\\rtA1
		uint32be(0) == 0x7B5C7274
		and 3 of ($rtf_olelink_*)
		and any of ($rtf_payload_*)
}
