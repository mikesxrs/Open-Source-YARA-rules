// Copyright 2021 by FireEye, Inc.
// You may not use this file except in compliance with the license. The license should have been received with this file.

rule FE_APT_Trojan_PL_QUIETPULSE 
{
    meta: 
        author = "Mandiant"  
        date_created = "2021-04-16"       
        md5 = "00575bec8d74e221ff6248228c509a16"
        reference_url = "https://www.fireeye.com/blog/threat-research/2021/04/suspected-apt-actors-leverage-bypass-techniques-pulse-secure-zero-day.html"
    strings: 
        $s1 = /open[\x09\x20]{0,32}\(\*STDOUT[\x09\x20]{0,32},[\x09\x20]{0,32}[\x22\x27]>&CLIENT[\x22\x27]\)/ 
        $s2 = /open[\x09\x20]{0,32}\(\*STDERR[\x09\x20]{0,32},[\x09\x20]{0,32}[\x22\x27]>&CLIENT[\x22\x27]\)/ 
        $s3 = /socket[\x09\x20]{0,32}\(SERVER[\x09\x20]{0,32},[\x09\x20]{0,32}PF_UNIX[\x09\x20]{0,32},[\x09\x20]{0,32}SOCK_STREAM[\x09\x20]{0,32},[\x09\x20]{0,32}0[\x09\x20]{0,32}\)[\x09\x20]{0,32};\s{0,128}unlink/ 
        $s4 = /bind[\x09\x20]{0,32}\([\x09\x20]{0,32}SERVER[\x09\x20]{0,32},[\x09\x20]{0,32}sockaddr_un\(/ 
        $s5 = /listen[\x09\x20]{0,32}\([\x09\x20]{0,32}SERVER[\x09\x20]{0,32},[\x09\x20]{0,32}SOMAXCONN[\x09\x20]{0,32}\)[\x09\x20]{0,32};/ 
        $s6 = /my[\x09\x20]{1,32}\$\w{1,64}[\x09\x20]{0,32}=[\x09\x20]{0,32}fork\([\x09\x20]{0,32}\)[\x09\x20]{0,32};\s{1,128}if[\x09\x20]{0,32}\([\x09\x20]{0,32}\$\w{1,64}[\x09\x20]{0,32}==[\x09\x20]{0,32}0[\x09\x20]{0,32}\)[\x09\x20]{0,32}\{\s{1,128}exec\(/ 
    condition: 
        all of them 
} 