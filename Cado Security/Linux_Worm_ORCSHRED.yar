rule Linux_Worm_ORCSHRED {
    meta:
    description = "Detects ORCSHRED worm used in attacks on Ukrainian ICS"
    reference = "https://github.com/cado-security/DFIR_Resources_Industroyer2"
	author = "mmuir@cadosecurity.com"
	date = "2022-04-12"
	license = "Apache License 2.0"
	hash = "43d07f28b7b699f43abd4f695596c15a90d772bfbd6029c8ee7bc5859c2b0861"
    strings:
    $a = "is_owner" ascii
	$b = "Start most security mode!" ascii
	$c = "check_solaris" ascii
	$d = "wsol.sh" ascii
	$e = "wobf.sh" ascii
	$f = "disown" ascii
	$g = "/var/log/tasks" ascii
    condition:
        4 of them
}
