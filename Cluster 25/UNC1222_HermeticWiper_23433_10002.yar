import "pe"
rule UNC1222_HermeticWiper_23433_10002 {
meta:
date = "2022-02-23"
description = "Detects HermeticWiper variants by internal strings"
hash1 = "0385eeab00e946a302b24a91dea4187c1210597b8e17cd9e2230450f5ece21da"
hash2 = "1bc44eef75779e3ca1eefb8ff5a64807dbc942b1e4a2672d77b9f6928d292591"
tlp = "white"
report = "https://blog.cluster25.duskrise.com/2022/02/24/ukraine-analysis-of-the-new-disk-wiping-malware"
strings:
$p1 = "$INDEX_ALLOCATION" wide
$p2 = "$I30" wide
$p3 = "$DATA" wide
$p4 = "$logfile" wide
$p5 = "$bitmap" wide
$s1 = "PhysicalDrive%u" wide
$s2 = "EPMNTDRV" wide
$s3 = "SYSVOL" wide
$s4 = "SYSTEM\\CurrentControlSet\\Control\\CrashControl" wide
$s5 = "CrashDumpEnabled" wide
$s6 = "NTFS" ascii
$s7 = "FAT" ascii
$s8 = "OpenSCManager" ascii
$s9 = "SeBackupPrivilege" wide
$s10 = "SeLoadDriverPrivilege" wide
$s11 = "RCDATA" wide
// LookupPrivilegeValueW routine
$r1 = { 85 35 2C 50 40 00 C7 84 ?? ?? ?? ?? 77 00 6E 00 C7 84 ?? ?? ?? ?? 50 00 72 00 8D 43 04 50 8D 44 24 44 50 6A 00 FF D6 8D 43 10 50 68 A8 55 40 00 6A 00 FF D6 6A 00 6A 00 6A 00 53 C7 03 02 00 00 00 6A 00 }
// AdjustTokenPrivileges routine
$r2 = { C7 43 0C 02 00 00 00 C7 43 18 02 00 00 00 FF 74 24 24 FF 15 28 50 40 00 FF D7 85 C0 75 0F }
// OpenSCManagerW (DatabaseName: "ServicesActive") routine
$r3 = { 68 ?? 3f 00 0f 00 68 ?? 80 55 44 00 33 f6 56 ff 15 24 50 40 00 89 44 24 10 85 C0 75 06 }
// OpenServiceW (ServiceName: "vss") routine
$r4 = { 68 ?? 58 40 00 50 FF 15 20 50 40 00 8B D8 85 DB 75 0C }
// ChangeServiceConfigW routine
$r5 = { 6A 00 6A 00 6A 00 6A 00 6A 00 6A 00 6A 00 6A FF 6A 04 6A 10 53 FF 15 14 50 40 00 85 C0 75 04 }
// CreateThread/CreateEventW and InitializeShutdownW routine
$r6 = { 8B 35 ?? ?? ?? ?? 8D 44 ?? ?? 6A 00 6A 00 50 68 ?? ?? 40 00 6A 00 6A 00 89 7C ?? ?? FF D6 6A 00 6A 00 6A 01 6A 00 89 44 ?? ?? FF 15 ?? ?? ?? ?? 6A 00 6A 00 89 44 ?? ?? 8D 44 ?? ?? 50 68 D0 34 40 00 6A 00 6A 00 FF D6 8B 3D D4 ?? ?? ?? 6B D8 85 DB 74 0A }
condition:
uint16(0)==0x5a4d and pe.imports("lz32.dll") and filesize < 200KB and (2 of ($p*) and (all of ($s*) or (6 of ($s*) and any of ($r*)) or 4 of ($r*)))
}