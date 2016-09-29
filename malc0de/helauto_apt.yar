rule helauto : apt
{
    strings:
        $a = "D-o-w-n-l-o-a-d-f-i-l-e%s******%d@@@@@@%d"
        $b = "%*s %d %s"
		$c = "cmd /c net stop RasAuto"
    condition:
        filesize < 100KB and (3 of ($a,$b,$c))
}