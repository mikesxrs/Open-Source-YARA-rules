rule Linux_Wiper_AWFULSHRED {
    meta:
        description = "Detects AWFULSHRED wiper used against Ukrainian ICS"
        reference = "https://github.com/cado-security/DFIR_Resources_Industroyer2"
        author = "mmuir@cadosecurity.com"
        date = "2022-04-12"
        license = "Apache License 2.0"
        hash = "bcdf0bd8142a4828c61e775686c9892d89893ed0f5093bdc70bde3e48d04ab99"
    strings:
        $isBash = "/bin/bash" ascii

	$a1 = "declare -r" ascii
	$a2 = "bash_history" ascii
	$a3 = "bs=1k if=/dev/urandom of=" ascii
	$a4 = "systemd" ascii
	$a5 = "apache http ssh" ascii
	$a6 = "shred" ascii

	$var1 = "iwljzfkg" ascii
	$var2 = "yrkdrrue" ascii
	$var3 = "agzerlyf" ascii
	$var4 = "rggygzny" ascii
	$var5 = "zubzgnvp" ascii
    condition:
        $isBash and 3 of ($a*) and 4 of ($var*)
}
