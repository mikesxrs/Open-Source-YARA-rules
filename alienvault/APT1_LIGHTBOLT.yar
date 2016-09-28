rule APT1_LIGHTBOLT
{
    meta:
        author = "AlienVault Labs"
        info = "CommentCrew-threat-apt1"

    strings:
        $str1 = "bits.exe" wide ascii
        $str2 = "PDFBROW" wide ascii
        $str3 = "Browser.exe" wide ascii
        $str4 = "Protect!" wide ascii
    condition:
        2 of them
}