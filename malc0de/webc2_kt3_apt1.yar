rule webc2_kt3 : apt
{
    strings:
        $a = "*!Kt3+v| s:"
        $b = "*!Kt3+v| dne"
		$c = "*!Kt3+v|"
    condition:
        filesize < 100KB and (3 of ($a,$b,$c))
}