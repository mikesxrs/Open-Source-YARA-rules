rule macromail : apt
{
    strings:
        $a = "get ok %d"
        $b = "put ok"
        $c = "GW-IP="
		$d = "messenger.hotmail.com"
		$e = "<d n=\"%s\">"
    condition:
        filesize < 300KB and (5 of ($a,$b,$c,$d,$e))
}