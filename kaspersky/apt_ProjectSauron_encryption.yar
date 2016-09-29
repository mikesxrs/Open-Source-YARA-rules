
import "pe"
import "math"

rule apt_ProjectSauron_encryption  {
meta:
	copyright = "Kaspersky Lab"
	description = "Rule to detect ProjectSauron string encryption"
	version = "1.0"
	reference = "https://securelist.com/blog/"


strings:

	$a1 = {81??02AA02C175??8B??0685}
	$a2 = {918D9A94CDCC939A93939BD18B9AB8DE9C908DAF8D9B9BBE8C8C9AFF}
	$a3 = {803E225775??807E019F75??807E02BE75??807E0309}

condition:
	filesize < 5000000 and
	any of ($a*)
}
