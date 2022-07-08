rule trojan_win_iis_shellsave : XEGroup
{
    meta:
        author = "threatintel@volexity.com"
        description = "Detects an AutoIT backdoor designed to run on IIS servers and to install a webshell. This rule will only work against memory samples."
        reference = "https://www.volexity.com/blog/2021/12/07/xe-group-exposed-8-years-of-hacking-card-skimming-for-profit/"
        date = "2021-11-17"
        hash1 = "21683e02e11c166d0cf616ff9a1a4405598db7f4adfc87b205082ae94f83c742"
        memory_suitable = 1
        license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"

    strings:
        $s1 = "getdownloadshell" ascii
        $s2 = "deleteisme" ascii 
        $s3 = "sitepapplication" ascii 
        $s4 = "getapplicationpool" ascii

    condition:
        all of them
}
