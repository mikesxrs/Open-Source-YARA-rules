rule FE_Hunting_BADRABBIT {
        meta:version=".2"
        filetype="PE"
        author="ian.ahl @TekDefense & nicholas.carr @itsreallynick"
        reference = "https://www.fireeye.com/blog/threat-research/2017/10/backswing-pulling-a-badrabbit-out-of-a-hat.html"
        date="2017-10-24"
        md5 = "b14d8faf7f0cbcfad051cefe5f39645f"
strings:
        // Messages
        $msg1 = "Incorrect password" nocase ascii wide
        $msg2 = "Oops! Your files have been encrypted." ascii wide
        $msg3 = "If you see this text, your files are no longer accessible." ascii wide
        $msg4 = "You might have been looking for a way to recover your files." ascii wide
        $msg5 = "Don't waste your time. No one will be able to recover them without our" ascii wide
        $msg6 = "Visit our web service at" ascii wide
        $msg7 = "Your personal installation key#1:" ascii wide
        $msg8 = "Run DECRYPT app at your desktop after system boot" ascii wide
        $msg9 = "Password#1" nocase ascii wide
        $msg10 = "caforssztxqzf2nm.onion" nocase ascii wide
        $msg11 = /partition (unbootable|not (found|mounted))/ nocase ascii wide

        // File references
        $fref1 = "C:\\Windows\\cscc.dat" nocase ascii wide
        $fref2 = "\\\\.\\dcrypt" nocase ascii wide
        $fref3 = "Readme.txt" ascii wide
        $fref4 = "\\Desktop\\DECRYPT.lnk" nocase ascii wide
        $fref5 = "dispci.exe" nocase ascii wide
        $fref6 = "C:\\Windows\\infpub.dat" nocase ascii wide
        // META
        $meta1 = "http://diskcryptor.net/" nocase ascii wide
        $meta2 = "dispci.exe" nocase ascii wide
        $meta3 = "GrayWorm" ascii wide
        $meta4 = "viserion" nocase ascii wide
        //commands
        $com1 = "ComSpec" ascii wide
        $com2 = "\\cmd.exe" nocase ascii wide
        $com3 = "schtasks /Create" nocase ascii wide
        $com4 = "schtasks /Delete /F /TN %ws" nocase ascii wide
condition:
        (uint16(0) == 0x5A4D)
        and
        (8 of ($msg*) and 3 of ($fref*) and 2 of ($com*))
        or
        (all of ($meta*) and 8 of ($msg*))
    }

rule FE_Trojan_BADRABBIT_DROPPER
    {
        meta:
            author = "muhammad.umair"
            md5 = "fbbdc39af1139aebba4da004475e8839"
            reference = "https://www.fireeye.com/blog/threat-research/2017/10/backswing-pulling-a-badrabbit-out-of-a-hat.html"
            rev = 1
        strings:
            $api1 = "GetSystemDirectoryW" fullword
            $api2 = "GetModuleFileNameW" fullword
            $dropped_dll = "infpub.dat" ascii fullword wide
            $exec_fmt_str = "%ws C:\\Windows\\%ws,#1 %ws" ascii fullword wide
            $extract_seq = { 68 ?? ?? ?? ?? 8D 95 E4 F9 FF FF 52 FF 15 ?? ?? ?? ?? 85 C0 0F 84 C4 00 00 00 8D 85 A8 ED FF FF 50 8D 8D AC ED FF FF E8 ?? ?? ?? ?? 85 C0 0F 84 AA 00 00 00 }
        condition:
            (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and filesize < 500KB and all of them
    }

rule FE_Worm_BADRABBIT
    {
        meta:
            author = "muhammad.umair"
            md5 = "1d724f95c61f1055f0d02c2154bbccd3"
            reference = "https://www.fireeye.com/blog/threat-research/2017/10/backswing-pulling-a-badrabbit-out-of-a-hat.html"
            rev = 1
        strings:
            $api1 = "WNetAddConnection2W" fullword
            $api2 = "CredEnumerateW" fullword
            $api3 = "DuplicateTokenEx" fullword
            $api4 = "GetIpNetTable"
            $del_tasks = "schtasks /Delete /F /TN drogon" ascii fullword wide
            $dropped_driver = "cscc.dat" ascii fullword wide
            $exec_fmt_str = "%ws C:\\Windows\\%ws,#1 %ws" ascii fullword wide
            $iter_encrypt = { 8D 44 24 3C 50 FF 15 ?? ?? ?? ?? 8D 4C 24 3C 8D 51 02 66 8B 31 83 C1 02 66 3B F7 75 F5 2B CA D1 F9 8D 4C 4C 3C 3B C1 74 07 E8 ?? ?? ?? ?? }
            $share_fmt_str = "\\\\%ws\\admin$\\%ws" ascii fullword wide
        condition:
            (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and filesize < 500KB and all of them
    }

rule FE_Trojan_BADRABBIT_MIMIKATZ
    {
        meta:
            author = "muhammad.umair"
            md5 = "37945c44a897aa42a66adcab68f560e0"
            reference = "https://www.fireeye.com/blog/threat-research/2017/10/backswing-pulling-a-badrabbit-out-of-a-hat.html"
            rev = 1
        strings:
            $api1 = "WriteProcessMemory" fullword
            $api2 = "SetSecurityDescriptorDacl" fullword
            $api_str1 = "BCryptDecrypt" ascii fullword wide
            $mimi_str = "CredentialKeys" ascii fullword wide
            $wait_pipe_seq = { FF 15 ?? ?? ?? ?? 85 C0 74 63 55 BD B8 0B 00 00 57 57 6A 03 8D 44 24 1C 50 57 68 00 00 00 C0 FF 74 24 38 4B FF 15 ?? ?? ?? ?? 8B F0 83 FE FF 75 3B }
        condition:
            (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and filesize < 500KB and all of them
    }

rule FE_Trojan_BADRABBIT_DISKENCRYPTOR
    {
        meta:
            author = "muhammad.umair"
            md5 = "b14d8faf7f0cbcfad051cefe5f39645f"
            reference = "https://www.fireeye.com/blog/threat-research/2017/10/backswing-pulling-a-badrabbit-out-of-a-hat.html"
            rev = 1
        strings:
            $api1 = "CryptAcquireContextW" fullword
            $api2 = "CryptEncrypt" fullword
            $api3 = "NetWkstaGetInfo" fullword
            $decrypt_seq = { 89 5D EC 78 10 7F 07 3D 00 00 00 01 76 07 B8 00 00 00 01 EB 07 C7 45 EC 01 00 00 00 53 50 53 6A 04 53 8B F8 56 89 45 FC 89 7D E8 FF 15 ?? ?? ?? ?? 8B D8 85 DB 74 5F }
            $msg1 = "Disk decryption progress..." ascii fullword wide
            $task_fmt_str = "schtasks /Create /SC ONCE /TN viserion_%u /RU SYSTEM /TR \"%ws\" /ST %02d:%02d:00" ascii fullword wide
            $tok1 = "\\\\.\\dcrypt" ascii fullword wide
            $tok2 = "C:\\Windows\\cscc.dat" ascii fullword wide
        condition:
            (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and filesize < 150KB and all of them
    }         
