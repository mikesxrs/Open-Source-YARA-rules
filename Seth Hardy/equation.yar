rule apt_equation_exploitlib_mutexes {

meta:
    author = "Kaspersky Lab"
    description = "Rule to detect Equation group's Exploitation library"
    version = "1.0"
    last_modified = "2015-02-16"
    reference = "https://securelist.com/blog/"

strings:
    $mz="MZ"
 
    $a1="prkMtx" wide
    $a2="cnFormSyncExFBC" wide
    $a3="cnFormVoidFBC" wide
    $a4="cnFormSyncExFBC" 
    $a5="cnFormVoidFBC"
 
condition:
  (($mz at 0) and any of ($a*))
}


rule apt_equation_doublefantasy_genericresource {

meta:
    author = "Kaspersky Lab"
    description = "Rule to detect DoubleFantasy encoded config"
    version = "1.0"
    last_modified = "2015-02-16"
    reference = "https://securelist.com/blog/"
 
strings:
    $mz="MZ"
    $a1={06 00 42 00 49 00 4E 00 52 00 45 00 53 00}
    $a2="yyyyyyyyyyyyyyyy"
    $a3="002"
 
condition:
  (($mz at 0) and all of ($a*))  and filesize < 500000
}


rule apt_equation_equationlaser_runtimeclasses {

meta:
    author = "Kaspersky Lab"
    description = "Rule to detect the EquationLaser malware"
    version = "1.0"
    last_modified = "2015-02-16"
    reference = "https://securelist.com/blog/"
 
strings:
    $a1="?a73957838_2@@YAXXZ"
    $a2="?a84884@@YAXXZ"
    $a3="?b823838_9839@@YAXXZ"
    $a4="?e747383_94@@YAXXZ"
    $a5="?e83834@@YAXXZ"
    $a6="?e929348_827@@YAXXZ"
 
condition:
    any of them
}


rule apt_equation_cryptotable {
 
meta:
    author = "Kaspersky Lab"
    description = "Rule to detect the crypto library used in Equation group malware"
    version = "1.0"
    last_modified = "2015-02-16"
    reference = "https://securelist.com/blog/"
 
strings:
    $a={37 DF E8 B6 C7 9C 0B AE 91 EF F0 3B 90 C6 80 85 5D 19 4B 45 44 12 3C E2 0D 5C 1C 7B C4 FF D6 05 17 14 4F 03 74 1E 41 DA 8F 7D DE 7E 99 F1 35 AC B8 46 93 CE 23 82 07 EB 2B D4 72 71 40 F3 B0 F7 78 D7 4C D1 55 1A 39 83 18 FA E1 9A 56 B1 96 AB A6 30 C5 5F BE 0C 50 C1}
 
 
condition:
    $a
}
