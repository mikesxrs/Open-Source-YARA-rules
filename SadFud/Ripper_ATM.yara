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
