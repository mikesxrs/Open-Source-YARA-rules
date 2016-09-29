rule apt_equation_equationlaser_runtimeclasses {
    meta:
        copyright = "Kaspersky Lab"
        description = "Rule to detect the EquationLaser malware"
        version = "1.0"
        last_modified = "2015-02-16"
        reference = "http://securelist.com/blog/research/68750/equation-the-death-star-of-malware-galaxy/"
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