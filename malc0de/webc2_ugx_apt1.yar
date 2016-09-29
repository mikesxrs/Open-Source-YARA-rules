rule webc2_ugx : apt
{
    strings:
        $a = "!@#dmc#@!"
        $b = "!@#tiuq#@!"
		$c = "!@#troppusnu#@!"
    condition:
        filesize < 100KB and (3 of ($a,$b,$c))
}