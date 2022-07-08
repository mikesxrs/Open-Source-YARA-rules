rule trojan_win_backwash_iis : XEGroup
{
    meta:
        author = "threatintel@volexity.com"
        date = "2020-09-04"
        description = "Variant of the BACKWASH malware family with IIS worm functionality."
        reference = "https://www.volexity.com/blog/2021/12/07/xe-group-exposed-8-years-of-hacking-card-skimming-for-profit/"
        hash = "98e39573a3d355d7fdf3439d9418fdbf4e42c2e03051b5313d5c84f3df485627"
        memory_suitable = 1
        license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"

    strings:
        $a1 = "GetShell" ascii 
        $a2 = "smallShell" ascii 
        $a3 = "createSmallShell" ascii 
        $a4 = "getSites" ascii 
        $a5 = "getFiles " ascii 

        $b1 = "action=saveshell&domain=" ascii wide
        $b2 = "&shell=backsession.aspx" ascii wide
        
    condition:
        all of ($a*) or 
        any of ($b*)
}
