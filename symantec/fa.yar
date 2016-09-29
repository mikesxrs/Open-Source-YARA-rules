rule fa
{
	meta:
 		author = "Symantec"
 		reference = "https://www.symantec.com/content/en/us/enterprise/media/security_response/whitepapers/waterbug-attack-group.pdf"

 	strings:
 		$mz = "MZ"
 		$string1 = "C:\\proj\\drivers\\fa _ 2009\\objfre\\i386\\atmarpd.pdb"

		$string2 = "d:\\proj\\cn\\fa64\\"
		$string3 = "sengoku _ Win32.sys\x00"
		$string4 = "rk _ ntsystem.c"
		$string5 = "\\uroboros\\"
		$string6 = "shell.{F21EDC09-85D3-4eb9-915F-1AFA2FF28153}"

	condition:
 		($mz at 0) and (any of ($string*))
}