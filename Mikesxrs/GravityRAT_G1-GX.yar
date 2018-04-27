rule GravityRAT_G1_PDB
{
	meta:
		author = "Michael Worth"
		reference = "https://blog.talosintelligence.com/2018/04/gravityrat-two-year-evolution-of-apt.html"
		description = "PDB path for Gravity RAT G1"

	strings:
		$PDB1 = "f:\\F\\Windows Work\\G1\\Adeel's Laptop\\G1 Main Virus\\systemInterrupts\\gravity\\obj\\x86\\Debug\\systemInterrupts.pdb"
		$PDB2 = "f:\\F\\Windows Work\\G1\\Adeel's Laptop\\"
       		$PDB3 = "\\gravity\\obj\\x86\\Debug\\"
	condition:
		any of them
}

rule GravityRAT_G2_PDB
{
	meta:
		author = "Michael Worth"
		reference = "https://blog.talosintelligence.com/2018/04/gravityrat-two-year-evolution-of-apt.html"
		description = "PDB path for Gravity RAT G2"

	strings:
		$PDB1 = "e:\\Windows Work\\G2\\G2 Main Virus\\Microsoft Virus Solutions (G2 v5) (Current)\\Microsoft Virus Solutions\\obj\\Debug\\Windows Wireless 802.11.pdb"
		$PDB2 = "e:\\Windows Work\\G2\\"
        	$PDB3 = "\\G2\\G2 Main Virus\\Microsoft Virus Solutions (G2"
	condition:
		any of them
}

rule GravityRAT_G3_PDB
{
	meta:
		author = "Michael Worth"
		reference = "https://blog.talosintelligence.com/2018/04/gravityrat-two-year-evolution-of-apt.html"
		description = "PDB path for Gravity RAT G3"

	strings:
		$PDB1 = "F:\\Projects\\g3\\G3 Version 4.0\\G3\\G3\\obj\\Release\\Intel Core.pdb"
		$PDB2 = "F:\\Projects\\g3\\G3 Version "
       		$PDB3 = "\\G3\\G3\\obj\\Release\\"
	condition:
		any of them
}

rule GravityRAT_GX_PDB
{
	meta:
		author = "Michael Worth"
		reference = "https://blog.talosintelligence.com/2018/04/gravityrat-two-year-evolution-of-apt.html"
		description = "PDB path for Gravity RAT GX"

	strings:
		$PDB1 = "C:\\Users\\The Invincible\\Desktop\\gx\\gx-current-program\\LSASS\\obj\\Release\\LSASS.pdb"
		$PDB2 = "C:\\Users\\The Invincible\\D"
       		$PDB3 = "Desktop\\gx\\gx-"
	condition:
		any of them
}



