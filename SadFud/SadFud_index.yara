//more info at reversecodes.wordpress.com
rule DMALocker
{
    meta:
    Description = "Deteccion del ransomware DMA Locker desde la version 1.0 a la 4.0"
    Author = "SadFud"
    Date = "30/05/2016"
    
    strings:
    $uno = { 41 42 43 58 59 5a 31 31 }
	  $dos = { 21 44 4d 41 4c 4f 43 4b }
	  $tres = { 21 44 4d 41 4c 4f 43 4b 33 2e 30 }
	  $cuatro = { 21 44 4d 41 4c 4f 43 4b 34 2e 30 }
    
    condition:
    any of them
    
}
//More at reversecodes.wordpress.com
rule DMALocker4.0
{
    meta:
    Description = "Deteccion del ransomware DMA Locker version 4.0"
    Author = "SadFud"
    Date = "30/05/2016"
	Hash = "e3106005a0c026fc969b46c83ce9aeaee720df1bb17794768c6c9615f083d5d1"
    
    strings:
    $clave = { 21 44 4d 41 4c 4f 43 4b 34 2e 30 }
    
    condition:
    $clave 
    
}
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
rule Ripper_ATM
{
    meta:
    Description = "RIPPER ATM MALWARE"
    Author = "SadFud"
    Date = "02/09/2016"
    Hash = "cc85e8ca86c787a1c031e67242e23f4ef503840739f9cdc7e18a48e4a6773b38"
    VT Scan = "https://www.virustotal.com/es/file/cc85e8ca86c787a1c031e67242e23f4ef503840739f9cdc7e18a48e4a6773b38/analysis/"
    
    strings:
    $a = { 6b 65 72 6e 79 76 40 6a 61 62 62 69 6d 2e 63 6f 6d }
	  
    
    condition:
    $a 
    
}
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
rule Malware.Gen.Vbs.Obfuscated
{
    meta:
    Description = "Deteccion de archivos visual basic script ofuscados"
    Author = "SadFud"
    Date = "28/05/2016"
    
    strings:
    $eg = { 45 78 65 63 75 74 65 47 6c 6f 62 61 6c } 
    $e = { 45 78 65 63 75 74 65 } 
    
    condition:
    $eg or $e
    
}
