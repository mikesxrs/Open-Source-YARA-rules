rule webc2_ausov : apt
{
    strings:
        $a = "ntshrui"
        $b = "Microsoft(R) Windows(R) Operating System"
    condition:
        filesize < 300KB and (2 of ($a,$b))
}