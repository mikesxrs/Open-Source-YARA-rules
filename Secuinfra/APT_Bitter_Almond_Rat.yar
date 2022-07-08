/*
Yara Rule Set
Author: SECUINFRA Falcon Team
Date: 2022-06-23
Identifier: 0x03-yara_win-Bitter_T-APT-17
Reference: "https://www.secuinfra.com/en/techtalk/whatever-floats-your-boat-bitter-apt-continues-to-target-bangladesh"
*/

/* Rule Set —————————————————————– */

import "pe"
import "dotnet"

rule APT_Bitter_Almond_RAT {

meta:
description = "Detects Bitter (T-APT-17) Almond RAT (.NET)"
author = "SECUINFRA Falcon Team (@SI_FalconTeam)"
tlp = "WHITE" reference = " https://www.secuinfra.com/en/techtalk/whatever-floats-your-boat-bitter-apt-continues-to-target-bangladesh"
date = "2022-06-01" hash = "55901c2d5489d6ac5a0671971d29a31f4cdfa2e03d56e18c1585d78547a26396"

strings:
$function0 = "GetMacid" ascii
$function1 = "StartCommWithServer" ascii
$function2 = "sendingSysInfo" ascii
$dbg0 = "*|END|*" wide
$dbg1 = "FILE>" wide
$dbg2 = "[Command Executed Successfully]" wide

condition:
uint16(0) == 0x5a4d
and dotnet.version == "v4.0.30319"
and filesize > 12KB // Size on Disk/1.5
and filesize < 68KB // Size of Image*1.5
and any of ($function*)
and any of ($dbg*)
}


