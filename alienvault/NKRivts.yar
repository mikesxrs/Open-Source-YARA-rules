rule rivts_pdb {
meta:
	description = "Detects Rivts based on PDB folder"
	author="cdoman@alienvault.com"
	tlp ="white"
	license = "MIT License"
    reference = "https://www.alienvault.com/blogs/security-essentials/north-korean-cyber-attacks-and-collateral-damage"
strings:
	$m = "F:\\meWork\\" nocase wide ascii
condition:
	uint16(0) == 0x5a4d and any of them
}
