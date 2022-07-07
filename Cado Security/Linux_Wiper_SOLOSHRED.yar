rule Linux_Wiper_SOLOSHRED {
    meta:
        description = "Detects SOLOSHRED wiper used against Ukrainian ICS"
        reference = "https://github.com/cado-security/DFIR_Resources_Industroyer2"
        author = "mmuir@cadosecurity.com"
        date = "2022-04-12"
        license = "Apache License 2.0"
        hash = "87ca2b130a8ec91d0c9c0366b419a0fce3cb6a935523d900918e634564b88028"
    strings:
        $a = "printenv | grep -i \"ora\"" ascii
        $b = "shred" ascii
	$c = "--no-preserve-root" ascii
        $d = "/dev/dsk" ascii
	$e = "$(ls /)" ascii
    condition:
        all of them
}
