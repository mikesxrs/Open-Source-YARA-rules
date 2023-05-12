rule crashoverride_configReader{
meta:
description = "CRASHOVERRIDE v1 Config File Parsing"
author = "Dragos Inc"
sha256 = "7907dd95c1d36cf3dc842a1bd804f0db511a0f68f4b3d382c23a3c974a383cad"
reference = "https://troopers.de/downloads/troopers18/TR18_DM_Mind-The-Gap.pdf"
strings:
$s0 = { 68 e8 ?? ?? ?? 6a 00 e8 a3 ?? ?? ?? 8b f8 83 c4 ?8 }
$s1 = { 8a 10 3a 11 75 ?? 84 d2 74 12 }
$s2 = { 33 c0 eb ?? 1b c0 83 c8 ?? }
$s3 = { 85 c0 75 ?? 8d 95 ?? ?? ?? ?? 8b cf ?? ?? }
condition:
uint16(0) == 0x5a4d and all of them
}
