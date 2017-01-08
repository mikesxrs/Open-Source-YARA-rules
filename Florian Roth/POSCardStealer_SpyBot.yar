rule POSCardStealer_SpyBot {
        meta:
                description = "POSCardStealer SpyBot Malware"
                author = "F. Roth"
                date = "2014-02-10"
                sha256 = "853fb5a2aad2e0533e390cfa5b0f3dfe96a054390cacdc8f4ba844bba20809e4"
                sha256 = "85c04c846b8e4a238b26cd96103a621f82242dd06ce0b8352d8f874c8387e1ae"
                sha256 = "e02e58cae7e61c4d93392c1a3e5f892d9bd053f28ec58b878c18a15ed2021613"
        strings:
                $s1 = "[BOT_ENGINE] - INFO - Created MUTEX: \"%s\"" wide
                $s2 = "\\Rescator\\uploader\\Debug\\scheck.pdb"
                $s3 = "data_%d_%d_%d_%d_%d.txt"

                $x1 = "BladeLogic"
                $x1 = "cmd /c net start %s"
                $x2 = "ftp -s:%s"
                $x3 = "PATH: %s"
                $x4 = "cmd.txt"
                $x6 = "COMMAND: %s"

        condition:
                1 of ($s*) or 4 of ($x*)
}
