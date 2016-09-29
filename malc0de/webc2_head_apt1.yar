rule webc2_head : apt
{
    strings:
        $a = "<head>"
        $b = "</head>"
		$c = "connect %s"
		$d = "https://"
		$e = "Ready!"
    condition:
        filesize < 100KB and (5 of ($a,$b,$c,$d,$e))
}