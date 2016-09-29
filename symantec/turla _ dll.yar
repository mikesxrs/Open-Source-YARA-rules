rule turla_dll
{
	
    meta:
 		Malware = "Trojan.Turla DLL"
 		author = "Symantec"
 		reference = "https://www.symantec.com/content/en/us/enterprise/media/security_response/whitepapers/waterbug-attack-group.pdf"
        
	strings:
		$a = /([A-Za-z0-9]{2,10} _ ){,2}Win32\.dll\x00/

	condition:
		pe.exports("ee") and $a
}
