rule HTTPBrowser
{
  meta:
    author = "mikesxrs"
    description = "PDB Path in httpbrowser malware"
    reference = "hhttps://www.secureworks.com/research/threat-group-3390-targets-organizations-for-cyberespionage"

  strings:
	$pdb1 = "J:\\TokenControlV3\\ServerDll\\Release\\ServerDll.pdb"
    
  condition:
    any of them
}
