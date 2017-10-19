rule Aurora_PDB
{
	meta:
		author = "Michael Worth"
		reference = "https://www.secureworks.com/blog/research-20913"
		description = "PDB path from Arora"

	strings:
		$PDB1 = "f:\\Aurora_Src\\AuroraVNC\\Avc\\Release\\AVC.pdb"
		$PDB2 = "f:\\Aurora_Src\\"
	condition:
		$PDB1 or $PDB2
}
