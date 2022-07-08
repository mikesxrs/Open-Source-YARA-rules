// Copyright 2021 by FireEye, Inc.
// You may not use this file except in compliance with the license. The license should have been received with this file.

rule FE_Webshell_PL_ATRIUM_1
{
    meta:
        author = "Mandiant"
        date_created = "2021-04-16"
        md5 = "ca0175d86049fa7c796ea06b413857a3"
        reference_url = "https://www.fireeye.com/blog/threat-research/2021/04/suspected-apt-actors-leverage-bypass-techniques-pulse-secure-zero-day.html"
    strings:
        $s1 = "CGI::param("
        $s2 = "system("
        $s3 = /if[\x09\x20]{0,32}\(CGI::param\([\x22\x27]\w{1,64}[\x22\x27]\)\)\s{0,128}\{[\x09\x20]{0,32}print [\x22\x27]Cache-Control: no-cache\\n[\x22\x27][\x09\x20]{0,32};\s{0,128}print [\x22\x27]Content-type: text\/html\\n\\n[\x22\x27][\x09\x20]{0,32};\s{0,128}my \$\w{1,64}[\x09\x20]{0,32}=[\x09\x20]{0,32}CGI::param\([\x22\x27]\w{1,64}[\x22\x27]\)[\x09\x20]{0,32};\s{0,128}system\([\x22\x27]\$/
    condition:
        all of them
}