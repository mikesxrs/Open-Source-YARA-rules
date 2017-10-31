rule REHASHED_PDB
{
	meta:
    	Author = "mikesxrs"
      Description = "Looking for unique PDB"
      Reference = "https://blog.fortinet.com/2017/09/05/rehashed-rat-used-in-apt-campaign-against-vietnamese-organizations"
      Date = "2017-09-05"
  strings:
		$PDB1 = "C:\\Users\\hoogle168\\Desktop\\2008Projects\\NewCoreCtrl08\\Release\\NewCoreCtrl08.pdb" ascii wide nocase
		$PDB2 = "C:\\Users\\hoogle168\\" ascii wide nocase
		$PDB3 = "\\NewCoreCtrl08\\Release\\NewCoreCtrl08.pdb" ascii wide nocase
	condition:
		any of them
}
