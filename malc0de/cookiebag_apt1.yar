rule cookiebag : apt
{
    strings:
        $a = "?ID="
        $b = ".asp"
        $c = "clientkey"
		$d = "GetCommand"
		$e = "Set-Cookie:"
    condition:
        filesize < 100KB and (5 of ($a,$b,$c,$d,$e))
}