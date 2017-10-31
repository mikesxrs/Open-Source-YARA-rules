rule FREEMILK_PDB
{
	meta:
    	Author = "mikesxrs"
        Description = "Looking for unique PDB"
        Reference = "https://researchcenter.paloaltonetworks.com/2017/10/unit42-freemilk-highly-targeted-spear-phishing-campaign/"
        Date = "2017-10-05"
  strings:
		$PDB1 = "E:\\BIG_POOH\\Project\\milk\\Release\\milk.pdb" ascii wide nocase
		$PDB2 = "E:\\BIG_POOH\\Project\\Desktop\\milk\\Release\\milk.pdb" ascii wide nocase
		$PDB3 = "E:\\BIG_POOH\\" ascii wide nocase
		$PDB4 = "\\Release\\milk.pdb" ascii wide nocase
		$PDB5 = "F:\\Backup\\2nd\\Agent\\Release\\Agent.pdb"
	condition:
		any of them
}
