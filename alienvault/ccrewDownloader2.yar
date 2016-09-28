rule ccrewDownloader2
{
    meta:
        author = "AlienVault Labs"
        info = "CommentCrew-threat-apt1"

  strings:
    $a = "3gZFQOBtY3sifNOl" wide ascii
        $b = "docbWUWsc2gRMv9HN7TFnvnKcrWUUFdAEem9DkqRALoD" wide ascii
        $c = "6QVSOZHQPCMc2A8HXdsfuNZcmUnIqWrOIjrjwOeagILnnScxadKEr1H2MZNwSnaJ" wide ascii

  condition:
    any of them
}