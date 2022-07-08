// Copyright 2021 by FireEye, Inc.
// You may not use this file except in compliance with the license. The license should have been received with this file.

rule FE_APT_Trojan_Linux32_LOCKPICK_1
{
    meta:
        author = "Mandiant"
        date_created = "2021-04-16"
        md5 = "e8bfd3f5a2806104316902bbe1195ee8"
        reference_url = "https://www.fireeye.com/blog/threat-research/2021/04/suspected-apt-actors-leverage-bypass-techniques-pulse-secure-zero-day.html"
    strings:
        $sb1 = { 83 ?? 63 0F 84 [4] 8B 45 ?? 83 ?? 01 89 ?? 24 89 44 24 04 E8 [4] 85 C0 }
        $sb2 = { 83 [2] 63 74 ?? 89 ?? 24 04 89 ?? 24 E8 [4] 83 [2] 01 85 C0 0F [5] EB 00 8B ?? 04 83 F8 02 7? ?? 83 E8 01 C1 E0 02 83 C0 00 89 44 24 08 8D 83 [4] 89 44 24 04 8B ?? 89 04 24 E8 }
    condition:
        ((uint32(0) == 0x464c457f) and (uint8(4) == 1)) and (@sb1[1] < @sb2[1])
}