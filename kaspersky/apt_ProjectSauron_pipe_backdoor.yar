import "pe"
import "math"

rule apt_ProjectSauron_pipe_backdoor  {
meta:
	copyright = "Kaspersky Lab"
	description = "Rule to detect ProjectSauron pipe backdoors"
	version = "1.0"    
	reference = "https://securelist.com/blog/"
   
strings:

	$a1 = "CreateNamedPipeW" fullword ascii
	$a2 = "SetSecurityDescriptorDacl" fullword ascii
	$a3 = "GetOverlappedResult" fullword ascii
	$a4 = "TerminateThread" fullword ascii
	$a5 = "%s%s%X" fullword wide
	

condition:
	uint16(0) == 0x5A4D 
	and (all of ($a*))
	and filesize < 100000
}