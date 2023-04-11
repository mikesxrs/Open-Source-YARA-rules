rule APT28_SkinnyBoy_Dropper: RUSSIAN THREAT ACTOR {
meta:
author = "Cluster25"
hash1 = "12331809c3e03d84498f428a37a28cf6cbb1dafe98c36463593ad12898c588c9"
report = "https://21649046.fs1.hubspotusercontent-na1.net/hubfs/21649046/2021-05_FancyBear.pdf"
strings:
$ = "cmd /c DEL " ascii
$ = " \"" ascii
$ = {8a 08 40 84 c9 75 f9}
$ = {0f b7 84 0d fc fe ff ff 66 31 84 0d fc fd ff ff}
condition:
(uint16(0) == 0x5A4D and all of them)
}