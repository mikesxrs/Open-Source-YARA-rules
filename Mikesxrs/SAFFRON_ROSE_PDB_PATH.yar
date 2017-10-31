rule SAFFRON_ROSE_PDB_PATH 
{
	meta:
    	Author = "@X0RC1SM"
    	Description = "Looking for unique pdb path"
	    Reference = "https://www.fireeye.com/content/dam/fireeye-www/global/en/current-threats/pdfs/rpt-operation-saffron-rose.pdf"
        
    strings:
    	$PDB1 = "d:\\svn\\Stealer\\source\\Stealer\\Stealer\\obj\\x86\\Release\\Stealer.pdb"
        $PDB2 = "f:\\Projects\\C#\\Stealer\\source\\Stealer\\Stealer\\obj\\x86\\Release\\Stealer.pdb"
    condition:
        any of them
}
