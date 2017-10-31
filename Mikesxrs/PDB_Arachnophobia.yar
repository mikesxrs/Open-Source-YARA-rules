rule PDB_Arachnophobia
{
	meta:
    	Author = "mikesxrs"
        Description = "Looking for unique PDB strings"
        Reference = "https://www.threatconnect.com/where-there-is-smoke-there-is-fire-south-asian-cyber-espionage-heats-up/Operation Arachnophobia"
        Date = "2017-10-28"
    strings:
    	$PDB1 = "C:\\Users\\Tranchulas\\Documents\\Visual Studio 2008\\Projects\\upload\\Release\\upload.pdb"
    	$PDB2 = "C:\\Users\\Cath\\documents\\visual studio 2010\\Projects\\ExtractPDF\\Release\\ExtractPDF.pdb"
    	$PDB3 = "C:\\Users\\Cath\\documents\\visual studio 2010\\Projects\\Start\\Release\\Start.pdb"
    	$PDB4 = "C:\\Users\\Cert-India\\Documents\\Visual Studio 2008\\Projects\\ufile\\Release\\ufile.pdb"
    	$PDB5 = "C:\\Users\\umairaziz27\\Documents\\Visual Studio 2008\\Projects\\usb\\Release\\usb.pdb"
    condition:
        any of them
}
