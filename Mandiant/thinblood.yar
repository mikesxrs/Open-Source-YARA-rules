// Copyright 2021 by FireEye, Inc.
// You may not use this file except in compliance with the license. The license should have been received with this file.

rule FE_APT_Tool_SH_THINBLOOD_1
{
    meta:
        author = "Mandiant" 
        date_created = "2021-04-16"
        sha256 = "1741dc0a491fcc8d078220ac9628152668d3370b92a8eae258e34ba28c6473b9"
        reference_url = "https://www.fireeye.com/blog/threat-research/2021/04/suspected-apt-actors-leverage-bypass-techniques-pulse-secure-zero-day.html"
    strings:
        $s1 = "sed -i \"s/.\\x00[^\\x00]*$2[^\\x00]*\\x09.\\x00//g"
        $s2 = "sed -i \"s/\\"
        $s3 = "\\x00[^\\x00]*$2[^\\x00]*\\x09\\x"
    condition:
        (filesize < 2048) and all of them
}