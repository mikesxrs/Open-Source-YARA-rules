rule APT3_PDB_Paths
{
	meta:
    	Author = "@X0RC1SM"
        Description = "Looking for PDB paths found in report"
        Reference1 = "https://www.fireeye.com/blog/threat-research/2014/11/operation_doubletap.html"
        Date = "2017-10-28"
    strings:
    	$PDB1 = "c:\\Users\\aa\\Documents\\Visual Studio 2008\\Projects\\MShell\\Release        \\MShell.pdb"
    	$PDB2 = "c:\\Users\\aa\\Documents\\Visual Studio 2008\\Projects\\4113\\Release            \\4113.pdb"
    	$PDB3 = "C:\\Users\\aa\\Documents\\Visual Studio 2010\\Projects\\MyRat\\Client\\Client      \\obj\\x86\\Release\\Client.pdb"
    	$PDB4 = "C:\\Users\\aa\\Documents\\"
    	$PDB5 = "c:\\Users\\aa\\Documents\\Visual Studio 2008\\Projects\\MShell\\Release\\MShell.pdb"
    	$PDB6 = "c:\\Users\\aa\\Documents\\Visual Studio 2008\\Projects\\4113\\Release\\4113.pdb"
    	$PDB7 = "C:\\Users\\aa\\Documents\\Visual Studio 2010\\Projects\\MyRat\\Client\\Client\\obj\\x86\\Release\\Client.pdb"

    condition:
        any of them
}
