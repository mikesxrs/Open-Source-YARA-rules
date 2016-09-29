rule gdocupload : apt
{
    strings:
        $a = "CONOUT$"
        $b = "length=%d,time=%fsec,speed=%fk"
		$c = "%s%s%s"
		$d = "http://docs.google.com/?auth="
		$e = "x-fpp-command: 0"
    condition:
        filesize < 300KB and (5 of ($a,$b,$c,$d,$e))
}