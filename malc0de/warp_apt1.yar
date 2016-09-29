rule warp : apt
{
    strings:
        $a = "Mozilla/4.0 (compatible; )"
        $b = "%u.%u.%u.%u"
        $c = "System info for machine"
		$d = "%2.2d-%2.2d-%4.4d %2.2d:%2.2d"
		$e = "https"
    condition:
        filesize < 300KB and (5 of ($a,$b,$c,$d,$e))
}