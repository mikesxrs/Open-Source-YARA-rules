rule APT1_WEBC2_KT3
{
    meta:
        author = "AlienVault Labs"
        info = "CommentCrew-threat-apt1"

    strings:
        $1 = "*!Kt3+v|" wide ascii
        $2 = " s:" wide ascii
        $3 = " dne" wide ascii
    condition:
        all of them
}