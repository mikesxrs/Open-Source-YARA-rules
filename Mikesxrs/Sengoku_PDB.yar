rule Sengoku_PDB
{
	meta:
    	Author = "@X0RC1SM"
        Description = "Looking for unique PDB"
        Reference = "http://artemonsecurity.com/snake_whitepaper.pdf"
        Date = "2017-10-28"
    strings:    
		$PDB1 = "d:\\proj\\cn\\fa64\\sengoku\\_bin\\sengoku\\win32_debug\\sengoku_Win32.pdb"  ascii wide nocase
		$PDB2 = "d:\\proj\\cn\\fa64\\sengoku\\" ascii wide nocase
		$PDB3 = "\\sengoku_Win32.pdb" ascii wide nocase
	condition:
		any of them
}










