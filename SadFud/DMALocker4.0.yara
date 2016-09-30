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
