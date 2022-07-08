// Copyright 2021 by FireEye, Inc.
// You may not use this file except in compliance with the license. The license should have been received with this file.

rule FE_APT_Webshell_PL_PULSECHECK_1 
{ 
    meta: 
        author = "Mandiant" 
        date_created = "2021-04-16"  
        sha256 = "a1dcdf62aafc36dd8cf64774dea80d79fb4e24ba2a82adf4d944d9186acd1cc1"
        reference_url = "https://www.fireeye.com/blog/threat-research/2021/04/suspected-apt-actors-leverage-bypass-techniques-pulse-secure-zero-day.html"
    strings: 
        $r1 = /while[\x09\x20]{0,32}\(<\w{1,64}>\)[\x09\x20]{0,32}\{\s{1,256}\$\w{1,64}[\x09\x20]{0,32}\.=[\x09\x20]{0,32}\$_;\s{0,256}\}/ 
        $s1 = "use Crypt::RC4;" 
        $s2 = "use MIME::Base64" 
        $s3 = "MIME::Base64::decode(" 
        $s4 = "popen(" 
        $s5 = " .= $_;" 
        $s6 = "print MIME::Base64::encode(RC4(" 
        $s7 = "HTTP_X_" 
    condition: 
        $s1 and $s2 and (@s3[1] < @s4[1]) and (@s4[1] < @s5[1]) and (@s5[1] < @s6[1]) and (#s7 > 2) and $r1 
} 