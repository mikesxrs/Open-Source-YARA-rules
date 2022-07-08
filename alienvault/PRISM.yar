rule PRISM {

    meta:

        author = "AlienLabs"

        description = "PRISM backdoor"

        reference = "https://github.com/andreafabrizi/prism/blob/master/prism.c"
        
        reference2 = "https://cybersecurity.att.com/blogs/labs-research/prism-attacks-fly-under-the-radar"


    strings:

        $s1 = "I'm not root :("

        $s2 = "Flush Iptables:\t"

        $s3 = " Version:\t\t%s\n"

        $s4 = " Shell:\t\t\t%s\n"

        $s5 = " Process name:\t\t%s\n"

        $s6 = "iptables -F 2> /dev/null"

        $s7 = "iptables -P INPUT ACCEPT 2> /dev/null"

        $s8 = " started\n\n# "


        $c1 = {

            E8 [4] 8B 45 ?? BE 00 00 00 00 89 C7 E8 [4] 8B 45 ?? BE 01 00 00 00

            89 C7 E8 [4] 8B 45 ?? BE 02 00 00 00 89 C7 E8 [4] BA 00 00 00 00

            BE [4] BF [4] B8 00 00 00 00 E8

        }

        $c2 = {

            BA 00 00 00 00

            BE 01 00 00 00

            BF 02 00 00 00

            E8 [4]

            89 45 [1]

            83 ?? ?? 00

        }


    condition:

        uint32(0) == 0x464C457F and

        filesize < 30KB and

        (4 of ($s*) or all of ($c*))

}

