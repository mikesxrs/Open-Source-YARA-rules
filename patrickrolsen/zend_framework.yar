rule zend_framework
{
meta:
	author = "@patrickrolsen"
	maltype = "Zend Framework"
	version = "0.3"
	date = "12/29/2013"
strings:
	$php = "<?php"
	$s = "$zend_framework" nocase
condition:
	not uint16(0) == 0x5A4D and $php and $s
}