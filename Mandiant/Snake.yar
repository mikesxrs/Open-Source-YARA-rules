rule Snake{

      meta:
            description = "Detects Snake"
            reference = "https://blogs.blackberry.com/en/2022/06/threat-thursday-unique-delivery-method-for-snake-keylogger"
            author = "BlackBerry Threat Research Team"
            date = "2022-06-03-"
            license = "This Yara rule is provided under the Apache License 2.0 (https://www.apache.org/licenses/LICENSE-2.0) and open to any user or organization, as long as you use it under this license and ensure originator credit in any derivative to The BlackBerry Research & Intelligence Team"

      strings:
            $s1 = "Game1Screen_Form_Load"
            $s2 = "get_KeyCode"
            $s3 = "Good luck mate"
 

      condition:
            filesize < 1000KB and all of them

}
