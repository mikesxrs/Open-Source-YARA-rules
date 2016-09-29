rule tarsip : apt
{
    strings:
        $a = "%s/%s?%s"
        $b = "Mozilla/4.0 (compatible; MSIE 6.0;"
        $c = "Can not xo file!"
		$d = "cnnd"
    condition:
        filesize < 100KB and (4 of ($a,$b,$c,$d))
}