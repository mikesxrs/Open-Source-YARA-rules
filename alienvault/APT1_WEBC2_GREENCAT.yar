rule APT1_WEBC2_GREENCAT
{
    meta:
        author = "AlienVault Labs"
        info = "CommentCrew-threat-apt1"

    strings:
        $1 = "reader_sl.exe" wide ascii
        $2 = "MS80547.bat" wide ascii
        $3 = "ADR32" wide ascii
        $4 = "ControlService failed!" wide ascii
    condition:
        3 of them
}