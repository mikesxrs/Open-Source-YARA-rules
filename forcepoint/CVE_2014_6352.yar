rule cve_2014_6352

{
meta:
  author = "Forcepoint"
  reference = "https://blogs.forcepoint.com/security-labs/ebola-spreads-cyber-attacks-too"
strings:

        $rootentry = {52 00 6F 00 6F 00 74 00 20 00 45 00 6E 00 74 00 72 00 79 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 16 00 05 00 ff ff ff ff ff ff ff ff 01 00 00 00}

        $ole10native = {4F 00 ( 4C | 6C ) 00 ( 45 | 65 ) 00 31 00 30 00 4E 00 61 00 74 00 69 00 76 00 65 00 00}

        $c = "This program cannot be run in DOS mode"

condition:

     ($rootentry or $ole10native) and $c

}
