rule COATHANGER_files
{
    meta:
        description = "Detects COATHANGER files by used filenames"
        malware = "COATHANGER"
        author = "NLD MIVD - JSCU"
        date = "20240206"
    strings:
        $1 = "/data2/"
        $2 = "/httpsd"
        $3 = "/preload.so"
        $4 = "/authd"
        $5 = "/tmp/packfile"
        $6 = "/smartctl"
        $7 = "/etc/ld.so.preload"
        $8 = "/newcli"
        $9 = "/bin/busybox"

    condition:
        (uint32(0) == 0x464c457f or uint32(4) == 0x464c457f)
        and filesize < 5MB and 4 of them
}
