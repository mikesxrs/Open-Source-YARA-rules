rule Elise
{
    meta:
        author = "AlienVault Labs"
        info = "CommentCrew-threat-apt1"

  strings:
    $a = "SetElise.pdb" wide ascii

  condition:
    $a
}