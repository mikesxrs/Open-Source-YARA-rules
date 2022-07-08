rule Windealer_executable{
      meta:
            description = "Detects WinDealer Executable"
            reference = "https://blogs.blackberry.com/en/2022/06/threat-thursday-china-based-apt-plays-auto-updater-card-to-deliver-windealer-malwareZ"
            author = "BlackBerry Threat Research Team"
            date = "2022-06-14"
            license = "This Yara rule is provided under the Apache License 2.0 (https://www.apache.org/licenses/LICENSE-2.0) and open to any user or organization, as long as you use it under this license and ensure originator credit in any derivative to The BlackBerry Research & Intelligence Team"


      strings:
            $s1 = "28e4-20a6acec"
            $s2 = "5a7e-42ccdb67"
            $s3 = "632c-0ef22957"
            $s4 = "63ae-a20cf808"
            $s5 = "65ce-731bffbb"
            $a1 = "remoteip"
            $a2 = "sessionid"
            $a3 = "remotedomain"
            $a4 = "remark"

      condition:
            uint16(0) == 0x5a4d and 2 of ($s*) and 1 of ($a*)
}
