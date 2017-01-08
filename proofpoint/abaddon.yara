rule AbaddonPOS
{
            meta:
                        description = "AbaddonPOS"
                        author = "Darien Huss, Proofpoint"
                        reference = "md5,317f9c57f7983e2608d5b2f00db954ff"
            strings:
                        $s1 = "devil_host" fullword ascii
                        $s2 = "Chrome" fullword ascii
                        $s3 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" fullword ascii

                        $i1 = { 31 ?? 81 ?? 55 89 E5 8B 74 }
            condition:
                        uint16(0) == 0x5a4d and (all of ($s*) or $i1) and filesize <= 10KB
}
