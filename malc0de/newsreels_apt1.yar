rule newsreels : apt
{
    strings:
        $a = "name=%s&userid=%04d&other=%c%s"
        $b = "thequickbrownfxjmpsvalzydg"
    condition:
        filesize < 300KB and (2 of ($a,$b))
}