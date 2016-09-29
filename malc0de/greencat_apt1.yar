rule greencat : apt
{
    strings:
        $a = "computer name:"
        $b = "McUpdate"
        $c = "%s\\%d.bmp"
		$d = "version: %s v%d.%d build %d%s"
		$e = "Ca Incert"
    condition:
        filesize < 300KB and (5 of ($a,$b,$c,$d,$e))
}