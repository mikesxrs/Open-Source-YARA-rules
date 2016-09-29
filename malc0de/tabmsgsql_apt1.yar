rule tabmsgsql : apt
{
    strings:
        $a = "accessip:%s"
        $b = "clientip:%s"
        $c = "Mozilla/4.0 (compatible; )"
		$d = "fromid:%s"
    condition:
        filesize < 300KB and (4 of ($a,$b,$c,$d))
}