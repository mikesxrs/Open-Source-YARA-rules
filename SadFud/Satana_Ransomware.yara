rule: Satana_Ransomware
{
	 meta:
    Description = "Deteccion de ransomware Satana"
    Author = "SadFud"
    Date = "12/07/2016"
	
	strings:
	$satana = { !satana! } nocase
	
	condition:
	$satana
}
