rule sword : apt
{
    strings:
        $a = "Agent%ld"
        $b = "thequickbrownfxjmpsvalzydg"
        $c = "down:"
		$d = "exit"
    condition:
        filesize < 100KB and (4 of ($a,$b,$c,$d))
}