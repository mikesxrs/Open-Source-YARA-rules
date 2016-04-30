rule bouncer2_exe : apt
{
    strings:
        $a = "asdfqwe123cxz"
        $b = "dump"
        $c = "loadlibrary kernel32 error %d"
    condition:
        filesize < 300KB and (3 of ($a,$b,$c))
}