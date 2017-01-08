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

