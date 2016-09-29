rule seasalt : apt
{
    strings:
        $a = "%4d-%02d-%02d %02d:%02d:%02d"
        $b = "upfileok"
        $c = "upfileer"
		$d = "configserver"
    condition:
        filesize < 300KB and (4 of ($a,$b,$c,$d))
}