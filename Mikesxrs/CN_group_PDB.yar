rule CN_group_PDB
{
	meta:
    	Author = "mikesxrs"
      Description = "Looking for unique 1937CN group PDB"
      Reference = "https://www.votiro.com/single-post/2017/08/23/Votiro-Labs-exposed-a-new-hacking-campaign-targeting-Vietnamese-organisations-using-a-weaponized-Word-documents"
		  Date = "2017-08-23"
	strings:
		$PDB1 = "G:\\Work\\Bison\\BisonNewHNStubDll\\Release\\Goopdate.pdb" ascii wide nocase
		$PDB2 = "G:\\Work\\Bison\\" ascii wide nocase
		$PDB3 = "\\BisonNewHNStubDll\\Release\\Goopdate.pdb" ascii wide nocase
	condition:
		any of them
}	
