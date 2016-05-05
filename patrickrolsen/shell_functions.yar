rule shell_functions
{
meta:
	author = "@patrickrolsen"
	version = "0.1"
	data = "08/19/2014"
	reference = "N/A"
strings:
	$s1 = "function listDatabases()"
	$s2 = "function dropDatabase()"
	$s3 = "mysql_drop_db("
	$s4 = "function listTables()"
	$s5 = "passthru($cmd)"
	$s6 = "function check_file()"
	$s7 = "$id==\"fake-mail\""
	$s8 = "Shell_Exec($cmd)"
	$s9 = "move_uploaded_file("
condition:
	not uint16(0) == 0x5A4D and any of ($s*)
}