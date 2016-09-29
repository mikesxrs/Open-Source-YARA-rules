import "pe"
rule mpress_2_xx_x86 : Packer
{
meta:
	author="Kevin Falcoz"
	date_create="19/03/2013"
	last_edit="24/03/2013"
	description="MPRESS v2.XX x86  - no .NET"

strings:
	$signature1={60 E8 00 00 00 00 58 05 5A 0B 00 00 8B 30 03 F0 2B C0 8B FE 66 AD C1 E0 0C 8B C8 50 AD 2B C8 03 F1 8B C8 57 51 49 8A 44 39 06 88 04 31 75 F6 2B C0 AC 8B C8 80 E1 F0 24} 
condition:
	$signature1 at (pe.entry_point)
}