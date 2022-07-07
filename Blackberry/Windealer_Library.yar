rule Windealer_Library{
      meta:
            description = "Detects WinDealer Loaded DLL"
            reference = "https://blogs.blackberry.com/en/2022/06/threat-thursday-china-based-apt-plays-auto-updater-card-to-deliver-windealer-malwareZ"
            author = "BlackBerry Threat Research Team"
            date = "2022-06-14"
            license = "This Yara rule is provided under the Apache License 2.0 (https://www.apache.org/licenses/LICENSE-2.0) and open to any user or organization, as long as you use it under this license and ensure originator credit in any derivative to The BlackBerry Research & Intelligence Team"


      strings:
            $s1 = "C:\\Users\\Public\\Documents\\Tencent\\QQ\\UserDataInfo.ini"
            $s2 = "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Shell Folders"
            $s3 = "SOFTWARE\\SogouInput\\red"
            $s4 = "SOFTWARE\\SogouDesktopBar"
            $s5 = "MozillaDll.dll"
            $s6 = "Tencent Files"
            $s7 = "wangwang"
            $s8 = "WeChat Files"
            $s9 = "MyDocument"
            $s10 = "Skype"
            $e1 = "AutoGetSystemInfo"
            $e2 = "GetConfigInfo"
            $e3 = "partInitOpt"
      condition:
            uint16(0) == 0x5a4d and all of them
}
