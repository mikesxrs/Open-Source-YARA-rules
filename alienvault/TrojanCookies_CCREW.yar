rule TrojanCookies_CCREW
{
    meta:
        author = "AlienVault Labs"
        info = "CommentCrew-threat-apt1"

  strings:
    $a = "sleep:" wide ascii
    $b = "content=" wide ascii
    $c = "reqpath=" wide ascii
    $d = "savepath=" wide ascii
    $e = "command=" wide ascii


  condition:
    4 of ($a,$b,$c,$d,$e)
}