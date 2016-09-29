rule webc2_y21k : apt
{
    strings:
        $a = "c2xlZXA="
        $b = "+Windows+NT+5.1"
		$c = "cXVpdA=="
    condition:
        filesize < 100KB and (3 of ($a,$b,$c))
}