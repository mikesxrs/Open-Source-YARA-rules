import "pe"
rule xdedic_packed_syscan {
	meta:
		author = "Kaspersky Lab"
		company = "Kaspersky Lab"
		reference = "https://securelist.com/files/2016/06/xDedic_marketplace_ENG.pdf"
	strings:
		$a1 = "SysScan.exe" nocase ascii wide
	condition:
		uint16(0) == 0x5A4D
		and any of ($a*) and filesize > 1000000 and filesize <1200000 and
		pe.number_of_sections == 13 and pe.version_info["FileVersion"] contains "1.3.4."
}