rule BoratRAT{

      meta:

            description = "Detects BoratRAT.exe"
            
            reference = "https://blogs.blackberry.com/en/2022/04/threat-thursday-boratrat"

            author = "BlackBerry Threat Research Team" 

            date = "2022-04-13"

            license = "This Yara rule is provided under the Apache License 2.0 (https://www.apache.org/licenses/LICENSE-2.0) and open to any user or organization, as long as you use it under this license and ensure originator credit in any derivative to The BlackBerry Research & Intelligence Team"

      strings:

            $s1 = "enigma1" 

            $s2 = "enigma2"

            $s3 = "Server.Forms.FormFileManager.resources"

            $s4 = "Server.Forms.FormFileSearcher.resources"

            $s5 = "Server.Forms.FormKeylogger.resources" 

            $s6 = "Server.Forms.FormNetstat.resources"

            $s7 = "Server.Forms.FormFun.resources"

            $s8 = "Server.Forms.FormWebcam.resources"

            $s9 = "BoratRat" 

            $s10 = "Keylogger.exe"

      condition:

            uint16(0) == 0x5a4d and all of them

} 
