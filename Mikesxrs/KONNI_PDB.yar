rule KONNI_PDB
{
  meta:
    author = "mikesxrs"
    description = "PDB Path in  malware"
    reference = "https://researchcenter.paloaltonetworks.com/2018/09/unit42-new-konni-malware-attacking-eurasia-southeast-asia/"

strings:
	$STR1= "C:\\Users\\zeus\\Documents\\Visual Studio 2010\\Projects\\virus-dropper\\Release\\virus-dropper.pdb" 
	$STR2= "C:\\Users\\zeus\\Documents\\Visual Studio 2010\\Projects\\"
    $STR3= "\\virus-dropper\\Release\\virus-dropper.pdb"
    
  condition: 
	any of them

}
