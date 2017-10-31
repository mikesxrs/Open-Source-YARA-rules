rule venom
{
    meta:
        description = "Venom Linux Rootkit"
        author = "Rich Walchuck"
        source = "https://security.web.cern.ch/security/venom.shtml"
        hash = "a5f4fc353794658a5ca2471686980569"
        date = "2017-01-31"

    strings:
        $string0 = "%%VENOM%OK%OK%%"
        $string1 = "%%VENOM%WIN%WN%%"
        $string2 = "%%VENOM%CTRL%MODE%%"
        $string3 = "%%VENOM%AUTHENTICATE%%"
        $string4 = "venom by mouzone"
        $string5 = "justCANTbeSTOPPED"

    condition:
        any of them
}
