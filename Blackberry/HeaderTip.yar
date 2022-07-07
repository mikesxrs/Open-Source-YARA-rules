rule HeaderTip{

      meta:
            description = "Detects HeaderTip"
            reference = "https://blogs.blackberry.com/en/2022/04/threat-thursday-headertip-backdoor-shows-attackers-from-china-preying-on-ukraine"
            author = "BlackBerry Threat Research Team"
            date = "2022-04-06-"

  license = "This Yara rule is provided under the Apache License 2.0 (https://www.apache.org/licenses/LICENSE-2.0) and open to any user or organization, as long as you use it under this license and ensure originator credit in any derivative to The BlackBerry Research & Intelligence Team"

      strings:
            $s1 = "type %temp%\\officecleaner.dat >> %objfile%"
            $s2 = "product2020.mrbasic.com" wide

      condition:
            filesize < 750KB and all of them

}
