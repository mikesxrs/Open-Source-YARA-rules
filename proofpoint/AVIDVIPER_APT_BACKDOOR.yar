rule AVIDVIPER_APT_BACKDOOR {

    meta:

        author = "Proofpoint Staff"

        info = "avid viper update"
		
		reference = "https://www.proofpoint.com/us/threat-insight/post/Operation-Arid-Viper-Slithers-Back-Into-View"
 

        strings:

                $s1 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-/"

                $s2 = "SELECT * FROM Win32_DiskDrive" wide ascii

                $s3 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" wide ascii

                $s4 = "\\dd\\vctools\\vc7libs\\ship\\atlmfc" wide ascii

        condition:

                $s4 and 2 of ($s1,$s2,$s3)

}
