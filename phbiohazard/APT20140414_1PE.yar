import "pe"

rule APT20140414_1PE
{
meta:
    author = "phbiohazard"
    reference = "https://github.com/phbiohazard/Yara"

strings:
    $genep1 = {04 01 68 9b 1a 40 00 6a 01 6a 00 6a 00 ff 15 0c}
    $genep2 = {e9 3d 87 f8 ff bb d6 fb 04 8a 10 5c d2 70 d9 cb}
    $genep3 = {57 56 8b f0 e8 70 fd ff ff 5e e8 6e 01 00 00 5f}
    $contep1 = {e9 02 47 83 c6 02 89 f2 83 f9 00}
    $contep2 = {e5 44 75 c1 8b 36 0c 44 4d c9 31 8b 8a d7 88 d8}
    $contep3 = {9c d1 d4 52 7b c5 99 29 1c d7 46 c5 f9 8c f8 e2}
    $contep4 = {e8 ef e4 bb 00 5d c3}
condition:
    $genep1 and $contep1 and $contep2 or ($genep2 at pe.entry_point and ($contep3 in (pe.entry_point..pe.entry_point + 65))) or ($genep3 at pe.entry_point and ($contep4 in (pe.entry_point..pe.entry_point + 26)))

}