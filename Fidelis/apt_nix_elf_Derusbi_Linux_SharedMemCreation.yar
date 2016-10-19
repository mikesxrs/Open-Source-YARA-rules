rule apt_nix_elf_Derusbi_Linux_SharedMemCreation
{
	meta: 
		author = "Fidelis Cybersecurity"
		reference = "https://www.fidelissecurity.com/resources/turbo-campaign-featuring-derusbi-64-bit-linux" 
	strings:
		$byte1 = { B6 03 00 00 ?? 40 00 00 00 ?? 0D 5F 01 82 }
	condition:
		(uint32(0) == 0x464C457F) and (any of them)
}



