rule COATHANGER_beacon
{
    meta:
        description = "Detects COATHANGER beaconing code (GET / HTTP/2\nHost: www.google.com\n\n)"
        malware = "COATHANGER"
        author = "NLD MIVD - JSCU"
        date = "20240206"
        report = "https://www.ncsc.nl/documenten/publicaties/2024/februari/6/mivd-aivd-advisory-coathanger-tlp-clear"
    strings:
        $chunk_1 = {
            48 B8 47 45 54 20 2F 20 48 54
            48 89 45 B0
            48 B8 54 50 2F 32 0A 48 6F 73
            48 89 45 B8
            48 B8 74 3A 20 77 77 77 2E 67
            48 89 45 C0
            48 B8 6F 6F 67 6C 65 2E 63 6F
        }

    condition:
        uint32(0) == 0x464c457f and filesize < 5MB and
        any of them
}
