rule longrun : apt
{
    strings:
        $a = "%s\\%c%c%c%c%c%c%c"
        $b = "thequickbrownfxjmpsvalzydg"
    condition:
        filesize < 300KB and (2 of ($a,$b))
}