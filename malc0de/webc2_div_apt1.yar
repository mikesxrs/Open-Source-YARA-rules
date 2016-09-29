rule webc2_div : apt
{
    strings:
        $a = "Microsoft Internet Explorer"
        $b = "Hello from MFC!"
		$c = "3DC76854-C328-43D7-9E07-24BF894F8EF5"
    condition:
        filesize < 100KB and (3 of ($a,$b,$c))
}
