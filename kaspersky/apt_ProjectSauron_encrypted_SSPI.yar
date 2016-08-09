
import "pe"
import "math"

rule apt_ProjectSauron_encrypted_SSPI  {
meta:
	copyright = "Kaspersky Lab"
	description = "Rule to detect encrypted ProjectSauron SSPI samples"
	version = "1.0"
	reference = "https://securelist.com/blog/"

condition:
	uint16(0) == 0x5A4D and
	filesize < 1000000 and
	pe.exports("InitSecurityInterfaceA") and
	pe.characteristics & pe.DLL and
	(pe.machine == pe.MACHINE_AMD64 or pe.machine == pe.MACHINE_IA64) and
	math.entropy(0x400, filesize) >= 7.5     
}