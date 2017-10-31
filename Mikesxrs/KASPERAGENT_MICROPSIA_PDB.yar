rule KASPERAGENT_MICROPSIA_PDB
{
	meta:
    	Author = "@X0RC1SM"
        Description = "Looking for unique PDB"
        Reference = "https://researchcenter.paloaltonetworks.com/2017/04/unit42-targeted-attacks-middle-east-using-kasperagent-micropsia/"
		    Reference2 = "http://www.clearskysec.com/micro-kasper/"
        Date = "2017-04-05"
  strings:
		$PDB1 = "C:\\Users\\USA\\Documents\\Visual Studio 2008\\Projects\\New folder (2)\\kasper\\Release\\kasper.pdb"
		$PDB2 = "C:\\Users\\Yousef\\Desktop\\MergeFiles\\Loader v0\\Loader\\obj\\Release\\Loader.pdb"
		$PDB3 = "c:\\Users\\USA\\Documents\\Visual Studio 2008\\Projects\\New folder (2)\\s7 - Copy - Copy 19-2-17\\Release\\s7.pdb"
		$PDB4 = "c:\\Users\\USA\\Documents\\Visual Studio 2008\\Projects\\New folder (2)\\s7\\Release\\s7.pdb"
		$PDB5 = "C:\\Users\\Progress\\Desktop\\Loader v0\\Loader\\obj\\Release\\Loader.pdb"
		$PDB6 = "D:\\Merge\\Debug\\testproj.pdb"
		$PDB7 = "c:\\Users\\USA\\Documents\\Visual Studio 2008\\Projects\\New folder (2)\\kasper - Copy - 21-2-17\\Release\\kasper.pdb"
		$PDB8 = "C:\\Users\\Yousef\\Desktop\\MergeFiles\\merge photos\\Loader v0\\Loader\\obj\\Release\\Loader.pdb"
		$PDB9 = "C:\\Users\\Yousef\\Desktop\\Loader v0\\Loader\\obj\\Release\\Loader.pdb"
		$PDB10 = "C:\\Users\\Yousef\\"
		$PDB11 = "C:\\Users\\USA\\Documents\\Visual Studio"
	condition:
		any of them
}
