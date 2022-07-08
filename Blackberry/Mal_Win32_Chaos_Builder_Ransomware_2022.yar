
import "pe"    

    rule Mal_Win32_Chaos_Builder_Ransomware_2022
{           
    meta:
    description = "Detects Chaos Ransomware Builder"
    reference = "https://blogs.blackberry.com/en/2022/05/yashma-ransomware-tracing-the-chaos-family-tree"
    author = "BlackBerry Threat Research"
    date = "2022-05-10"
    license = "This Yara rule is provided under the Apache License 2.0 (https://www.apache.org/licenses/LICENSE-2.0) and open to any user or organization, as long as you use it under this license and ensure originator credit in any derivative to The BlackBerry Research & Intelligence Team"

            strings:

                        $s0 = "1qw0ll8p9m8uezhqhyd" ascii wide

                        $s1 = "Chaos Ransomware Builder" ascii wide

                        $s2 = "payloadFutureName" ascii wide

                        $s3 = "read_it.txt" ascii wide

                        $s4 = "encryptedFileExtension" ascii wide

 

                        $x0 = "1098576" ascii wide

                        $x1 = "2197152" ascii wide

            condition:

//PE File

                        uint16(0) == 0x5a4d and

 

                        //All strings

                        ((all of ($s*)) and (1 of ($x*)))


}
