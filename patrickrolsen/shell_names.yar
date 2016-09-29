rule shell_names
{
meta:
	author = "@patrickrolsen"
	version = "0.3"
	data = "08/19/2014"
	reference = "N/A"
strings:
	$s1 = "faim.php"
	$s2 = "css5.php"
	$s3 = "groanea.php"
	$s4 = "siler.php"
	$s5 = "w.php" fullword
	$s6 = "atom-conf.php"
	$s7 = "405.php"
	$s8 = "pack2.php"
	$s9 = "r57shell.php"
	$s10 = "shell.php" fullword
	$s11 = "dra.php"
	$s12 = "lol.php"
	$s13 = "php-backdoor.php"
	$s14 = "aspxspy.aspx"
	$s15 = "c99.php"
	$s16 = "c99shell.php"
	$s17 = "fx29sh.php"
	$s18 = "azrailphp.php"
	$s19 = "CmdAsp.asp"
	$s20 = "dingen.php"
	$s21 = "entrika.php"
condition:
	not uint16(0) == 0x5A4D and any of ($s*)
}