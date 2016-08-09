
import "pe"
import "math"

rule apt_ProjectSauron_encrypted_container  {
meta:
	copyright = "Kaspersky Lab"
	description = "Rule to detect ProjectSauron samples encrypted container"
	version = "1.0"
	reference = "https://securelist.com/blog/"

strings:

	$vfs_header = {02 AA 02 C1 02 0?}
	$salt = {91 0A E0 CC 0D FE CE 36 78 48 9B 9C 97 F7 F5 55}

condition:
	uint16(0) == 0x5A4D
	and ((@vfs_header < 0x4000) or $salt) and
	math.entropy(0x400, filesize) >= 6.5 and
	(filesize > 0x400) and filesize < 10000000
}