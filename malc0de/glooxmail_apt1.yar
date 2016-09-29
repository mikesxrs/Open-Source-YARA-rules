rule glooxmail : apt
{
    strings:
        $a = "This is gloox"
        $b = "Getfile Abrot!"
        $c = "glooxtest"
    condition:
        filesize < 100KB and (3 of ($a,$b,$c))
}
