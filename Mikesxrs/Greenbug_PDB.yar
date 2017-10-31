rule Greenbug_PDB
{
	meta:
    	Author = "mikesxrs"
        Description = "Looking for unique PDB"
        Reference = "https://researchcenter.paloaltonetworks.com/2017/07/unit42-oilrig-uses-ismdoor-variant-possibly-linked-greenbug-threat-group/"
		    Reference2 = "http://www.clearskysec.com/greenbug/"
        Date = "2017-04-05"
  strings:
		    $PDB1 = "C:\\Users\\Void\\Desktop\\v 10.0.194\\x64\\Release\\swchost.pdb" ascii wide nocase
        $PDB2 = "C:\\Users\\Void\\Desktop\\" ascii wide nocase
		    $PDB3 = "\\Release\\swchost.pdb" ascii wide nocase
	condition:
		any of them
}
