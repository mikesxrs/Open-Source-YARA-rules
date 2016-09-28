rule ccrewQAZ
{
    meta:
        author = "AlienVault Labs"
        info = "CommentCrew-threat-apt1"

  strings:
    $a = "!QAZ@WSX" wide ascii

  condition:
    $a
}