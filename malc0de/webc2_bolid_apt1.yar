rule webc2_bolid : apt
{
    strings:
        $a = ".htmlEEEEEEEEEEEEEEEEEEEEEEEEEEEEsleep:"
        $b = "downloadcopy:"
		$c = "geturl:"
		$d = "Q3JlYXRlUHJvY2Vzc0E="
    condition:
        filesize < 100KB and (4 of ($a,$b,$c,$d))
}