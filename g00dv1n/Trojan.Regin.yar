rule Regin_APT_KernelDriver_Generic_A {
        meta:
		        Description = "Trojan.Regin.A.sm"
				ThreatLevel = "5"
        strings:
                $m1 = { 0e 1f ba 0e 00 b4 09 cd 21 b8 01 4c cd 21 54 68 69 73 20 70 72 6f 67 72 61 6d 20 63 61 6e 6e 6f 74 20 62 65 20 72 75 6e 20 69 6e 20 44 4f 53 20 6d 6f 64 65 2e }

                $s0 = "atapi.sys" fullword wide
                $s1 = "disk.sys" fullword wide
                $s3 = "h.data" fullword ascii
                $s4 = "\\system32" fullword ascii
                $s5 = "\\SystemRoot" fullword ascii
                $s6 = "system" fullword ascii
                $s7 = "temp" fullword ascii
                $s8 = "windows" fullword ascii

                $x1 = "LRich6" fullword ascii
                $x2 = "KeServiceDescriptorTable" fullword ascii
        condition:
                $m1 and all of ($s*) and 1 of ($x*)
}

rule Regin_APT_KernelDriver_Generic_B {
        meta:
				Description = "Trojan.Regin.B.sm"
				ThreatLevel = "5"
        strings:
                $s1 = { 0e 1f ba 0e 00 b4 09 cd 21 b8 01 4c cd 21 54 68 69 73 20 70 72 6f 67 72 61 6d 20 63 61 6e 6e 6f 74 20 62 65 20 72 75 6e 20 69 6e 20 44 4f 53 20 6d 6f 64 65 2e }
                $s2 = "H.data" fullword ascii nocase
                $s3 = "INIT" fullword ascii
                $s4 = "ntoskrnl.exe" fullword ascii

                $v1 = "\\system32" fullword ascii
                $v2 = "\\SystemRoot" fullword ascii
                $v3 = "KeServiceDescriptorTable" fullword ascii

                $w1 = "\\system32" fullword ascii
                $w2 = "\\SystemRoot" fullword ascii
                $w3 = "LRich6" fullword ascii

                $x1 = "_snprintf" fullword ascii
                $x2 = "_except_handler3" fullword ascii

                $y1 = "mbstowcs" fullword ascii
                $y2 = "wcstombs" fullword ascii
                $y3 = "KeGetCurrentIrql" fullword ascii

                $z1 = "wcscpy" fullword ascii
                $z2 = "ZwCreateFile" fullword ascii
                $z3 = "ZwQueryInformationFile" fullword ascii
                $z4 = "wcslen" fullword ascii
                $z5 = "atoi" fullword ascii
        condition:
                all of ($s*) and ( all of ($v*) or all of ($w*) or all of ($x*) or all of ($y*) or all of ($z*) )
}

rule Regin_APT_KernelDriver_Generic_C {
        meta:
				Description = "Trojan.Regin.C.sm"
				ThreatLevel = "5"
                /*description = "Generic rule for Regin APT kernel driver Malware - Symantec http://t.co/qu53359Cb2"
                author = "@Malwrsignatures - included in APT Scanner THOR"
                date = "23.11.14"
                hash1 = "e0895336617e0b45b312383814ec6783556d7635"
                hash2 = "732298fa025ed48179a3a2555b45be96f7079712"  */
        strings:

                $s0 = "KeGetCurrentIrql" fullword ascii
                $s1 = "5.2.3790.0 (srv03_rtm.030324-2048)" fullword wide
                $s2 = "usbclass" fullword wide

                $x1 = "PADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDING" ascii
                $x2 = "Universal Serial Bus Class Driver" fullword wide
                $x3 = "5.2.3790.0" fullword wide

                $y1 = "LSA Shell" fullword wide
                $y2 = "0Richw" fullword ascii
        condition:
                all of ($s*) and ( all of ($x*) or all of ($y*) )
}

rule Regin_sig_svcsstat {
        meta:
				Description = "Trojan.Regin.sm"
				ThreatLevel = "5"
                /*description = "Detects svcstat from Regin report - file svcsstat.exe_sample"
                author = "@Malwrsignatures"
                date = "25.11.14"
                score = 70
                hash = "5164edc1d54f10b7cb00a266a1b52c623ab005e2"*/
        strings:
                $s0 = "Service Control Manager" fullword ascii
                $s1 = "_vsnwprintf" fullword ascii
                $s2 = "Root Agency" fullword ascii
                $s3 = "Root Agency0" fullword ascii
                $s4 = "StartServiceCtrlDispatcherA" fullword ascii
                $s5 = "\\\\?\\UNC" fullword ascii
                $s6 = "%ls%ls" fullword wide
        condition:
                all of them and filesize < 15KB and filesize > 10KB
}