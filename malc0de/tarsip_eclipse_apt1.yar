rule tarsip_eclipse : apt
{
    strings:
        $a = "Eclipse"
        $b = "PIGG"
        $c = "WAKPDT"
		$d = "show.asp?"
		$e = "flink?"
    condition:
        filesize < 300KB and (5 of ($a,$b,$c,$d,$e))
}
