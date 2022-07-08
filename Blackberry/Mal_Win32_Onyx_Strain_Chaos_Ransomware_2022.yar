import "pe"    

    rule Mal_Win32_Onyx_Strain_Chaos_Ransomware_2022
{           
    meta:
    description = "Detects Onyx Ransomware build off of Chaos Builder v4"
    reference = "https://blogs.blackberry.com/en/2022/05/yashma-ransomware-tracing-the-chaos-family-tree"
    author = "BlackBerry Threat Research"
    date = "2022-05-10"
    license = "This Yara rule is provided under the Apache License 2.0 (https://www.apache.org/licenses/LICENSE-2.0) and open to any user or organization, as long as you use it under this license and ensure originator credit in any derivative to The BlackBerry Research & Intelligence Team"

            strings:
            $s1 = "(?:[13]{1}[a-km-zA-HJ-NP-Z1-9]{26,33}|bc1[a-z0-9]{39,59})" wide
            $s2 = "All of your files are currently encrypted by ONYX strain." wide
            $s3 = "Inform your supervisors and stay calm!" wide

            condition:

            //PE File
            uint16(0) == 0x5a4d and

            //Directories
            pe.data_directories[pe.IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR].size != 0 and

            //All strings
            all of ($s*)

}

