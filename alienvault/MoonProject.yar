rule MoonProject
{
    meta:
        author = "AlienVault Labs"
        info = "CommentCrew-threat-apt1"

  strings:
    $a = "Serverfile is smaller than Clientfile" wide ascii
    $b = "\\M tools\\" wide ascii
    $c = "MoonDLL" wide ascii
        $d = "\\M tools\\" wide ascii

  condition:
    any of them
}