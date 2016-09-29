rule webc2_adspace : apt
{
    strings:
        $a = "ntshrui"
        $b = "Microsoft(R) Windows(R) Operating System"
    condition:
        filesize < 100KB and (2 of ($a,$b))
}