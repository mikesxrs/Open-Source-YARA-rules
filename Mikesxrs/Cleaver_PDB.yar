rule Cleaver_PDB
{
	meta:
    	Author = "@X0RC1SM"
        Description = "Looking for unique PDB"
        Reference = "https://www.cylance.com/content/dam/cylance/pages/operation-cleaver/Cylance_Operation_Cleaver_Report.pdf"
        Date = "2017-10-28"
    strings:    
		$PDB1 = "e:\\projects\\cleaver\\trunk\\zhoupin_cleaver\\obj\\x86\\release\\netscp.pdb"  ascii wide nocase
		$PDB2 = "c:\\users\\jimbp\\desktop\\binder_1 - for cleaver\\binder_1\\obj\\x86\\release\\setup.pdb" ascii wide nocase
		$PDB3 = "e:\\Projects\\Cleaver\\trunk\\MainModule\\obj\\Release\\MainModule.pdb" ascii wide nocase
		$PDB4 = "e:\\projects\\cleaver\\" ascii wide nocase 
		$PDB5 = "c:\\users\\jimbp\\" ascii wide nocase
		$PDB6 = "zhoupin_cleaver\\" ascii wide nocase
		$PDB7 = "\\Projects\\Cleaver\\" ascii wide nocase 
		$PDB8 = "\\binder_1 - for cleaver\\" ascii wide nocase
	condition:
		any of them
}
