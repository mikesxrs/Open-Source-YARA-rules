rule dairy : apt
{
    strings:
        $a = "%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c"
        $b = "Mozilla/4.0 (compatible; MSIE 7.0;)"
        $c = "dir %temp%"
		$d = "pklist"
		$e = "pkkill"
    condition:
        filesize < 100KB and (5 of ($a,$b,$c,$d,$e))
}