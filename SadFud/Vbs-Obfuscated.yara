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
