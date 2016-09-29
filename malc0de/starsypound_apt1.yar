rule starsypound : apt
{
    strings:
        $a = "*(SY)# cmd"
        $b = "send = %d"
        $c = "cmd.exe"
		$d = "COMSPEC"
    condition:
        filesize < 100KB and (4 of ($a,$b,$c,$d))
}