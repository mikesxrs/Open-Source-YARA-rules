rule QUIETEXIT_strings

{

    meta:

        author = "Mandiant"
        
        reference = "https://www.mandiant.com/resources/unc3524-eye-spy-email"

        date_created = "2022-01-13"

        date_modified = "2022-01-13"

        rev = 1

    strings:

        $s1 = "auth-agent@openssh.com"

        $s2 = "auth-%.8x-%d"

        $s3 = "Child connection from %s:%s"

        $s4 = "Compiled without normal mode, can't run without -i"

        $s5 = "cancel-tcpip-forward"

        $s6 = "dropbear_prng"

        $s7 = "cron"

    condition:

        uint32be(0) == 0x7F454C46 and filesize < 2MB and all of them

}
