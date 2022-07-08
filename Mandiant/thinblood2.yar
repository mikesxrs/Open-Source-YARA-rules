// Copyright 2021 by FireEye, Inc.
// You may not use this file except in compliance with the license. The license should have been received with this file.

rule FE_APT_Tool_Linux_THINBLOOD_1
{
    meta:
        author = "Mandiant" 
        date_created = "2021-04-16"
        sha256 = "88170125598a4fb801102ad56494a773895059ac8550a983fdd2ef429653f079"
        reference_url = "https://www.fireeye.com/blog/threat-research/2021/04/suspected-apt-actors-leverage-bypass-techniques-pulse-secure-zero-day.html"
    strings:
        $ss1 = "\x00Clearlog success!\x00"
        $ss2 = "\x00Select log file:%s\x0a\x00"
        $ss3 = "\x00clearlog success\x00"
        $ss4 = "\x00%s match %d records\x0a\x00"
    condition:
        (uint32(0) == 0x464c457f) and all of them
}