rule APT1_WEBC2_CSON
{
    meta:
        author = "AlienVault Labs"
        info = "CommentCrew-threat-apt1"

    strings:
        $httpa1 = "/Default.aspx?INDEX=" wide ascii
        $httpa2 = "/Default.aspx?ID=" wide ascii
        $httpb1 = "Win32" wide ascii
        $httpb2 = "Accept: text*/*" wide ascii
        $exe1 = "xcmd.exe" wide ascii
        $exe2 = "Google.exe" wide ascii
    condition:
        1 of ($exe*) and 1 of ($httpa*) and all of ($httpb*)
}