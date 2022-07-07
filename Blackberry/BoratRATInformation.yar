rule BoratRATInformation{ 

      meta:

            description = "Detects BoratRAT Information Module"
            
            reference = "https://blogs.blackberry.com/en/2022/04/threat-thursday-boratrat"

            author = "BlackBerry Threat Research Team"

            date = "2022-04-13" 

            license = "This Yara rule is provided under the Apache License 2.0 (https://www.apache.org/licenses/LICENSE-2.0) and open to any user or organization, as long as you use it under this license and ensure originator credit in any derivative to The BlackBerry Research & Intelligence Team"

      strings:

            $s1 = "set_UseShellExecute"

            $s2 = "execCMD" 

            $s3 = "hostname" wide

            $s4 = "ipconfig" wide

            $s5 = "tasklist" wide

            $s6 = "arp -a" wide 

            $sp = {43 3A 5C 55 73 65 72 73 5C 41 64 6D 69 6E 69 

                   73 74 72 61 74 6F 72 5C 44 6F 77 6E 6C 6F 61 

                   64 73 5C 53 61 6E 74 61 52 61 74 2D 6D 61 69 

                   6E 5C 42 69 6E 61 72 69 65 73 5C 52 65 6C 65  

                   61 73 65 5C 50 6C 75 67 69 6E 73 5C 49 6E 66 

                   6F 72 6D 61 74 69 6F 6E 2E 70 64 62}

      condition:

            uint16(0) == 0x5a4d and all of them 

}
