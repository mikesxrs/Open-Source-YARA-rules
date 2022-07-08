// Copyright 2021 by FireEye, Inc.
// You may not use this file except in compliance with the license. The license should have been received with this file.

rule FE_APT_Webshell_PL_SLIGHTPULSE_1
{
    meta:
        author = "Mandiant" 
        date_created = "2021-04-16"
        sha256 = "133631957d41eed9496ac2774793283ce26f8772de226e7f520d26667b51481a"
        reference_url = "https://www.fireeye.com/blog/threat-research/2021/04/suspected-apt-actors-leverage-bypass-techniques-pulse-secure-zero-day.html"
    strings:
        $r1 = /if[\x09\x20]{0,32}\(CGI::param\([\x22\x27]\w{1,64}[\x22\x27]\)[\x09\x20]{0,32}\)[\x09\x20]{0,32}\{[\x09\x20]{0,32}[\x09\x20]{0,32}\w{1,64}\([\x09\x20]{0,32}\)[\x09\x20]{0,32}\x3b[\x09\x20]{0,32}\}[\x09\x20]{0,32}elsif/
        $r2 = /system[\x09\x20]{0,32}\([\x09\x20]{0,32}[\x22\x27]\$\w{1,64}[\x09\x20]{0,32}>[\x09\x20]{0,32}\/tmp\/\d{1,10}[\x09\x20]{1,32}2[\x09\x20]{0,32}>[\x09\x20]{0,32}&1[\x22\x27][\x09\x20]{0,32}\)[\x09\x20]{0,32}\x3b\s{0,128}open[\x09\x20]{0,32}\([\x09\x20]{0,32}\*\w{1,64}[\x09\x20]{0,32},[\x09\x20]{0,32}[\x22\x27][\x09\x20]{0,32}<[\x09\x20]{0,32}\$\w{1,64}[\x22\x27][\x09\x20]{0,32}\)[\x09\x20]{0,32}\x3b\s{0,128}while[\x09\x20]{0,32}\([\x09\x20]{0,32}<[\x09\x20]{0,32}\w{1,64}[\x09\x20]{0,32}\>[\x09\x20]{0,32}\)[\x09\x20]{0,32}\{/
        $s1 = "CGI::param("
        $s2 = "system("
        $s3 = "Content-type: image/gif\\n\\n" nocase
    condition:
        all of them
}