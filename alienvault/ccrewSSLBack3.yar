rule ccrewSSLBack3
{
    meta:
        author = "AlienVault Labs"
        info = "CommentCrew-threat-apt1"

  strings:
    $a = "SLYHKAAY" wide ascii

  condition:
    any of them
}