rule Final1stspy_PDB
{
  meta:
    author = "mikesxrs"
    description = "PDB Path in  malware"
    reference = "https://researchcenter.paloaltonetworks.com/2018/10/unit42-nokki-almost-ties-the-knot-with-dogcall-reaper-group-uses-new-malware-to-deploy-rat/"

strings:
	$STR1= "E:\\Final Project(20180108)\\Final1stspy\\LoadDll\\Release\\LoadDll.pdb"
    $STR2= "E:\\Final Project(20180108)\\Final1stspy\\hadowexecute – Copy\\Release\\hadowexecute.pdb"
    $STR3= "E:\\Final Project(20180108)\\Final1stspy\\"

    
  condition: 
	any of them

}
