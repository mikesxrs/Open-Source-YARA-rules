/*
Yara Rule Set
Author: SECUINFRA Falcon Team
Date: 2022-06-23
Identifier: 0x03-yara_win-Bitter_T-APT-17
Reference: "https://www.secuinfra.com/en/techtalk/whatever-floats-your-boat-bitter-apt-continues-to-target-bangladesh"
*/

/* Rule Set —————————————————————– */

rule APT_Bitter_ZxxZ_Downloader {

meta:
description = "Detects Bitter (T-APT-17) ZxxZ Downloader"
author = "SECUINFRA Falcon Team (@SI_FalconTeam)"
tlp = "WHITE"
reference = " https://www.secuinfra.com/en/techtalk/whatever-floats-your-boat-bitter-apt-continues-to-target-bangladesh"
date = "2022-06-01"
hash0 = "91ddbe011f1129c186849cd4c84cf7848f20f74bf512362b3283d1ad93be3e42"
hash1 = "90fd32f8f7b494331ab1429712b1735c3d864c8c8a2461a5ab67b05023821787"
hash2 = "69b397400043ec7036e23c225d8d562fdcd3be887f0d076b93f6fcaae8f3dd61"
hash3 = "3fdf291e39e93305ebc9df19ba480ebd60845053b0b606a620bf482d0f09f4d3"
hash4 = "fa0ed2faa3da831976fee90860ac39d50484b20bee692ce7f0ec35a15670fa92"

strings:
// old ZxxZ samples / decrypted strings
$old0 = "MsMp" ascii
$old1 = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion" ascii
$old2 = "&&user=" ascii
$old3 = "DN-S" ascii
$old4 = "RN_E" ascii

// new ZxxZ samples
$c2comm0 = "GET /" ascii
$c2comm1 = "profile" ascii
$c2comm2 = ".php?" ascii
$c2comm3 = "data=" ascii
$c2comm4 = "Update" ascii
$c2comm5 = "TTT" ascii

condition:
uint16(0) == 0x5a4d
and filesize > 39KB // Size on Disk/1.5
and filesize < 2MB // Size of Image*1.5

and (all of ($old*)) or (all of ($c2comm*))

}

