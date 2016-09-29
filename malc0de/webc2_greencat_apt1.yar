rule webc2_greencat : apt
{
    strings:
        $a = "shell"
        $b = "getf/putf FileName <N>"
		$c = "kill </p|/s> <pid|ServiceName>"
		$d = "list </p|/s|/d>"
    condition:
        filesize < 100KB and (4 of ($a,$b,$c,$d))
}