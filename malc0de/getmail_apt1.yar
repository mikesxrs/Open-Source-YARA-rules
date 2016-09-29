rule getmail : apt
{
    strings:
        $a = "Lu's Zany Message Store"
        $b = "IP"
		$c = "%s%i %s%i"
		$d = "-c key too long(MAX=16)"
		$e = "-f file name too long"
    condition:
        filesize < 300KB and (5 of ($a,$b,$c,$d,$e))
}