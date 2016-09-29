rule calendar : apt
{
    strings:
        $a = "DownRun success"
        $b = "GoogleLogin auth="
        $c = "%s@gmail.com"
		$d = "log command"
		$e = "%s: %s"
    condition:
        filesize < 300KB and (5 of ($a,$b,$c,$d,$e))
}
