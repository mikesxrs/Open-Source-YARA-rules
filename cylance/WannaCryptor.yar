import "pe"

rule WannaCry_Ransomware_Dropper
{
  meta:
    description = "WannaCry Ransomware Dropper"
    reference = "https://www.cylance.com/en_us/blog/threat-spotlight-inside-the-wannacry-attack.html"
    date = "2017-05-12"

  strings:
    $s1 = "cmd.exe /c \"%s\"" fullword ascii
    $s2 = "tasksche.exe" fullword ascii
    $s3 = "icacls . /grant Everyone:F /T /C /Q" fullword ascii
    $s4 = "Global\\MsWinZonesCacheCounterMutexA" fullword ascii

  condition:
    uint16(0) == 0x5a4d and 
    filesize < 4MB and 
    all of them
}

rule WannaCry_SMB_Exploit
{
  meta:
    description = "WannaCry SMB Exploit"
    reference = "https://www.cylance.com/en_us/blog/threat-spotlight-inside-the-wannacry-attack.html"
    date = "2017-05-12"

  strings:
    $s1 = { 53 4D 42 72 00 00 00 00 18 53 C0 00 00 00 00 00 00 00 00 00 00 00 00 00 00 FF FE 00 00 40 00 00 62 00 02 50 43 20 4E 45 54 57 4F 52 4B 20 50 52 4F 47 52 41 4D 20 31 2E 30 00 02 4C 41 4E 4D 41 4E 31 2E 30 00 02 57 69 6E 64 6F 77 73 20 66 6F 72 20 57 6F 72 6B 67 72 6F 75 70 73 20 33 2E 31 61 00 02 4C 4D 31 2E 32 58 30 30 32 00 02 4C 41 4E 4D 41 4E 32 2E 31 00 02 4E 54 20 4C 4D 20 30 2E 31 32 00 00 00 00 00 00 00 88 FF 53 4D 42 73 00 00 00 00 18 07 C0 }

  condition:
    uint16(0) == 0x5a4d and
    filesize < 4MB and 
    all of them and
    pe.imports("ws2_32.dll", "connect") and
    pe.imports("ws2_32.dll", "send") and
    pe.imports("ws2_32.dll", "recv") and
    pe.imports("ws2_32.dll", "socket") and
    pe.imports("ws2_32.dll", "closesocket")
}
