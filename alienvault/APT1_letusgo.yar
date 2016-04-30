rule APT1_letusgo
{
    meta:
        author = "AlienVault Labs"
        info = "CommentCrew-threat-apt1"

    strings:
        $letus = /letusgo[\w]+v\d\d?\./
    condition:
        $letus
}