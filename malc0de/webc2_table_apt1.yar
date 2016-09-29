rule webc2_table : apt
{
    strings:
        $a = "<![<endif>]--->"
        $b = "CreateThread() failed: %d"
		$c = "class="
    condition:
        filesize < 100KB and (3 of ($a,$b,$c))
}