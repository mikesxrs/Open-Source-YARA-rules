rule webc2_rave : apt
{
    strings:
        $a = "HTTP Mozilla/5.0(compatible+MSIE)"
        $b = "123!@#qweQWE"
		$c = "%s\\%s"
    condition:
        filesize < 100KB and (3 of ($a,$b,$c))
}