// Copyright 2021 by FireEye, Inc.
// You may not use this file except in compliance with the license. The license should have been received with this file.

rule FE_APT_Trojan_PL_RADIALPULSE_1 
{
    meta: 
        author = "Mandiant" 
        date_created = "2021-04-16"       
        sha256 = "d72daafedf41d484f7f9816f7f076a9249a6808f1899649b7daa22c0447bb37b"
        reference_url = "https://www.fireeye.com/blog/threat-research/2021/04/suspected-apt-actors-leverage-bypass-techniques-pulse-secure-zero-day.html"        
    strings: 
        $s1 = "->getRealmInfo()->{name}" 
        $s2 = /open\(\*fd,[\x09\x20]{0,32}[\x22\x27]>>/ 
        $s3 = /syswrite\(\*fd,[\x09\x20]{0,32}[\x22\x27]realm=\$/ 
        $s4 = /syswrite\(\*fd,[\x09\x20]{0,32}[\x22\x27]username=\$/ 
        $s5 = /syswrite\(\*fd,[\x09\x20]{0,32}[\x22\x27]password=\$/ 
    condition: 
        (@s1[1] < @s2[1]) and (@s2[1] < @s3[1]) and $s4 and $s5 
} 