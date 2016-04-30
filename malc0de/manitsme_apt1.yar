rule manitsme : apt
{
    strings:
        $a = "rouji"
        $b = "Visual Studio"
        $c = "UglyGorilla"
    condition:
        filesize < 300KB and (5 of ($a,$b,$c))
}