rule sav_dropper
{
	meta:
 		author = "Symantec"
 		malware = "SAV dropper"
 		reference = "https://www.symantec.com/content/en/us/enterprise/media/security_response/whitepapers/waterbug-attack-group.pdf"
 	
    strings:
 		$mz = "MZ"
 		$a = /[a-z]{,10} _ x64.sys\x00hMZ\x00/
 	
    condition:
 		($mz at 0) and uint32(0x400) == 0x000000c3 and pe.number_of_sections == 6 and $a
}