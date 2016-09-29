rule miniasp : apt
{
    strings:
        $a = ".asp?device_t=%s&key=%s&device_id=%s&cv=%s"
        $b = "result=%s"
        $c = "command=%s"
		$d = "wakeup="
    condition:
        filesize < 300KB and (4 of ($a,$b,$c,$d))
}