rule mapiget : apt
{
    strings:
        $a = "WNetCancelConnection2W"
        $b = "WNetAddConnection2W"
		$c = "%s -f:filename"
		$d = "CreateProcessWithLogonW"
		$e = "127.0.0.1"
    condition:
        filesize < 300KB and (5 of ($a,$b,$c,$d,$e))
}