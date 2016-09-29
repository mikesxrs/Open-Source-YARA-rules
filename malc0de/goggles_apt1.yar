rule goggles : apt
{
    strings:
        $a = "thequickbrownfxjmpsvalzydg"
        $b = "Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 5.1; Trident/4.0; %s.%s)"
    condition:
        filesize < 200KB and (2 of ($a,$b))
}