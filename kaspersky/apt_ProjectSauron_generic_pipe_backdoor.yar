
import "pe"
import "math"

rule apt_ProjectSauron_generic_pipe_backdoor {
meta:
	copyright = "Kaspersky Lab"
	description = "Rule to detect ProjectSauron generic pipe backdoors"
	version = "1.0"
	reference = "https://securelist.com/blog/"

strings:
	$a = { C7 [2-3] 32 32 32 32 E8 }
	$b = { 42 12 67 6B }
	$c = { 25 31 5F 73 }
	$d = "rand"
	$e = "WS2_32"

condition:
	uint16(0) == 0x5A4D and
	(all of them) and
	filesize < 400000
}