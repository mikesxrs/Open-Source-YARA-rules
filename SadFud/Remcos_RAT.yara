rule Remcos_RAT
{
    meta:
    Description = "Deteccion del troyano Remcos"
    Author = "SadFud"
    Date = "08/08/2016"
	  Hash = "f467114dd637c817b4c982fad55fe019"
    
    strings:
    $a = { 52 45 4d 43 4f 53 }
	  $b = { 52 65 6d 63 6f 73 5f 4d 75 74 65 78 }
    
    condition:
    $a or $b 
    
}
