rule bouncer_exe : apt
{
    strings:
        $a = "*Qd9kdgba33*%Wkda0Qd3kvn$*&><(*&%$E#%$#1234asdgKNAg@!gy565dtfbasdg"
        $b = "dump"
        $c = "IDR_DATA%d"
    condition:
        filesize < 300KB and (3 of ($a,$b,$c))
}