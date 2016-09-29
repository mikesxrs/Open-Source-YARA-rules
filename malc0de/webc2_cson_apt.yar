rule webc2_cson : apt
{
    strings:
        $a = "/Default.aspx?INDEX="
        $b = "/Default.aspx?ID="
		$c = "Windows+NT+5.1"
		$d = "<!--"
    condition:
        filesize < 100KB and (4 of ($a,$b,$c,$d))
}
