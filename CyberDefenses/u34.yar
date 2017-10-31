rule php_shell_U34 {
meta:
		description = "Web Shell - file ans.php"
		author = "Monty St John"
		company = "Cyberdefenses, inc."
		date = "2017/01/25"
		hash = "5be3b1bc76677a70553a66575f289a0a"
strings:
$a = "'\".((strpos(@$_POST['"
$b = "'],\"\\n\")!==false)?'':htmlspecialchars(@$_POST['"
$c = "'],ENT_QUOTES)).\"';"
$d = "posix_getpwuid"
condition:
  all of them 
}
