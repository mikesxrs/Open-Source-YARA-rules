rule combos : apt
{
    strings:
        $a = "showthread.php?t="
        $b = "Getfile"
        $c = "Putfile"
		$d = "file://"
		$e = "https://%s"
    condition:
        filesize < 300KB and (5 of ($a,$b,$c,$d,$e))
}