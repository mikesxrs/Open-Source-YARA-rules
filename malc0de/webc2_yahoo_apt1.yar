rule webc2_yahoo : apt
{
    strings:
        $a = "<yahoo sb="
        $b = "<yahoo ex="
		$c = "letusgo"
    condition:
        filesize < 100KB and (3 of ($a,$b,$c))
}