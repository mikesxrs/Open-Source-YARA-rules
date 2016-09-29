rule lightdart : apt
{
    strings:
        $a = "0123456789ABCDEF"
        $b = "ErrCode=%ld"
        $c = "ret.log"
        $d = "Microsoft Internet Explorer 6.0"
        $e = "szURL"
    condition:
        filesize < 200KB and (5 of ($a,$b,$c,$d,$e))
}
