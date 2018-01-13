rule crime_win32_gratefulpos_trojan {
        meta:
                description = "GratefulPOS malware variant"
                author = "@VK_Intel"
                reference = "Detects GratefulPOS"
                reference = "http://www.vkremez.com/2017/12/lets-learn-reversing-grateful-point-of.html"
                date = "2017-12-10"
        strings:
                $s0 = "conhost.exe" fullword ascii
                $s1 = "del logmeinlauncher.exe" fullword ascii
                $s2 = "Chrome.exe" fullword ascii
                $s3 = "taskmgr.exe" fullword ascii
                $s4 = "firefox.exe" fullword ascii
                $s5 = "logmeinlauncher.exe stop" fullword ascii
                $s6 = "ping 1.1.1.1 -n 1 -w 3000 > nul" fullword ascii
                $s7 = "Ymscoree.dll" fullword wide
                $s8 = "LogMeInHamachi Process Launcher" fullword ascii
                $s9 = "sched.exe" fullword ascii
                $s10 = "wininit.exe" fullword ascii
                $s11 = "wmiprvse.exe" fullword ascii
                $s12 = "RegSrvc.exe" fullword ascii
                $s13 = "mdm.exe" fullword ascii
                $s14 = "GET /index.php HTTP/1.0" fullword ascii
                $s15 = "LogMeIn Hamachi Launcher" fullword ascii
                $s16 = "logmein.bid" fullword ascii
                $s17 = "del sd.bat" fullword ascii
                $s18 = "sd.bat" fullword ascii
        condition:
                uint16(0) == 0x5a4d and filesize < 500KB and 10 of them
}
