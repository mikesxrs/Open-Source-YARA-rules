rule bouncer_dll : apt
{
    strings:
        $a = "select"
        $b = "%s: %s"
        $c = "sa:%s"
		$d = ";PWD="
		$e = "Computer Numbers: %d"
    condition:
        filesize < 350KB and (5 of ($a,$b,$c,$d,$e))
}
