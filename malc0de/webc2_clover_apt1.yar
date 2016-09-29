rule webc2_clover : apt
{
    strings:
        $a = "m i c r o s o f t"
        $b = "Default.asp"
		$c = "background="
		$d = "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1)"
    condition:
        filesize < 100KB and (4 of ($a,$b,$c,$d))
}