rule kurton : apt
{
    strings:
        $a = "HttpsUp||"
        $b = "!(*@)(!@PORT!(*@)(!@URL"
        $c = "root\\%s"
		$d = "HttpsFile||"
		$e = "Config service %s ok"
    condition:
        filesize < 300KB and (5 of ($a,$b,$c,$d,$e))
}