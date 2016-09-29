rule auriga : apt
{
    strings:
        $a = "%.2x%.2x-%.2x%.2x-%.2x%.2x-%.2x%.2x-%.2x%.2x-%.2x%.2x"
        $b = "auriga"
        $c = "McUpdate"
        $d = "download"
        $e = "upload"
    condition:
        filesize < 300KB and (5 of ($a,$b,$c,$d,$e))
}