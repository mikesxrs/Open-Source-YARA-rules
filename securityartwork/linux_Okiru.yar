rule LinuxOkiru: MALW
{
	meta:
		description = "Linux.Okiru"
		author = "Joan Soriano / @w0lfvan"
		reference = "https://www.securityartwork.es/2017/12/18/analisis-linux-okiru/"
		date = "2017-11-03"
		version = "1.0"
		MD5 = "0e1e8079cc78cd242dd70867bc30c8d1"
		SHA256 = "601ad06dd9de8c19c196441f4a405c95dbd752c95fb017fda6c4fc7ca6d86d9c"
	strings:
		$a = "/usr/dvr_main _8182T_1108"
		$b = "/var/Challenge"
		$c = "/mnt/mtd/app/gui"
	condition:
		all of them
}
