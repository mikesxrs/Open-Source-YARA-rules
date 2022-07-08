rule Backdoor_Win_C3_1
{
    meta:
        author = "FireEye"
        date_created = "2021-05-11"
        description = "Detection to identify the Custom Command and Control (C3) binaries."
        reference = "https://www.mandiant.com/resources/shining-a-light-on-darkside-ransomware-operations"
        md5 = "7cdac4b82a7573ae825e5edb48f80be5"
    strings:
        $dropboxAPI = "Dropbox-API-Arg"
        $knownDLLs1 = "WINHTTP.dll" fullword
        $knownDLLs2 = "SHLWAPI.dll" fullword
        $knownDLLs3 = "NETAPI32.dll" fullword
        $knownDLLs4 = "ODBC32.dll" fullword
        $tokenString1 = { 5B 78 5D 20 65 72 72 6F 72 20 73 65 74 74 69 6E 67 20 74 6F 6B 65 6E }
        $tokenString2 = { 5B 78 5D 20 65 72 72 6F 72 20 63 72 65 61 74 69 6E 67 20 54 6F 6B 65 6E }
        $tokenString3 = { 5B 78 5D 20 65 72 72 6F 72 20 64 75 70 6C 69 63 61 74 69 6E 67 20 74 6F 6B 65 6E }
    condition:
        filesize < 5MB and uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550 and (((all of ($knownDLLs*)) and ($dropboxAPI or (1 of ($tokenString*)))) or (all of ($tokenString*)))
    }
