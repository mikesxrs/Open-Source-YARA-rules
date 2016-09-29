rule webc2_qbp : apt
{
    strings:
        $a = "%t?%d-%d-%d="
        $b = "Hello@)!0"
		$c = "?id="
    condition:
        filesize < 100KB and (3 of ($a,$b,$c))
}