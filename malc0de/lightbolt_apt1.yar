rule lightbolt : apt
{
    strings:
        $a = "bits.exe a all.jpg .\\ALL -hp%s"
        $b = "The %s store has been opened"
		$c = "Machine%d"
		$d = "Service%d"
		$e = "7z;ace;arj;bz2;cab;gz;jpeg;jpg;lha;lzh;mp3;rar;taz;tgz;z;zip"
    condition:
        filesize < 300KB and (5 of ($a,$b,$c,$d,$e))
}