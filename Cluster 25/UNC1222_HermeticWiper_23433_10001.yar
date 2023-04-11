rule UNC1222_HermeticWiper_23433_10001 {
meta:
date = "2022-02-23"
description = "Detects HermeticWiper variants by internal strings"
author = "Cluster25"
tlp = "white"
hash1 = "0385eeab00e946a302b24a91dea4187c1210597b8e17cd9e2230450f5ece21da"
hash2 = "1bc44eef75779e3ca1eefb8ff5a64807dbc942b1e4a2672d77b9f6928d292591"
report = "https://blog.cluster25.duskrise.com/2022/02/24/ukraine-analysis-of-the-new-disk-wiping-malware"
strings:
$ = "tdrv.pdb" fullword ascii
$ = "\\\\.\\EPMNTDRV\\%u" fullword wide
$ = "PhysicalDrive%u" fullword wide
$ = "Hermetica Digital Ltd"
condition:
(uint16(0) == 0x5a4d and all of them)
}