rule CobianRAT { 
meta: 
  	description = "Yara Rule for Cobian RAT in Aggah Wayback campaign" 
  	author = "Yoroi Malware Zlab" 
    reference = "https://yoroi.company/research/the-wayback-campaign-a-large-scale-operation-hiding-in-plain-sight/"
  	last_updated = "2021_06_18" 
  	tlp = "white" 
  	category = "informational" 

strings: 
$s1="bWFzdGVy" wide
$s2="Ydmzipw~" wide 

$a1={11 8E B7 16 FE 01 5F 2C 46 1B 8D 1D} 
$a2={07 17 D6 0B 07 1A 30 20 14 0C 07 B5 1F 64 28 33} 

condition: 
   uint16(0) == 0x5A4D and any of ($s*) and 1 of ($a*)
} 
