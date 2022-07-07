rule web_js_xeskimmer : XEGroup
{
    meta:
        author = "threatintel@volexity.com"
        description = "Detects JScript code using in skimming credit card details."
        date = "2021-11-17"
        hash1 = "92f9593cfa0a28951cae36755d54de63631377f1b954a4cb0474fa0b6193c537"
        reference1 = "https://blog.malwarebytes.com/threat-analysis/2020/07/credit-card-skimmer-targets-asp-net-sites/"
        reference2 = "https://github.com/MBThreatIntel/skimmers/blob/master/null_gif_skimmer.js"
        reference3 = "https://www.volexity.com/blog/2021/12/07/xe-group-exposed-8-years-of-hacking-card-skimming-for-profit/"
        memory_suitable = 0
        license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"

    strings:
        $s1 = ".match(/^([3456]\\d{14,15})$/g" ascii
        $s2 = "^(p(wd|ass(code|wd|word)))" ascii
        
        $b1 = "c('686569676874')" ascii
        $b2 = "c('7769647468')" ascii

        $c1 = "('696D67')" ascii
        $c2 = "('737263')" ascii

        $magic = "d=c.charCodeAt(b),a+=d.toString(16);" 
        
    condition:
        all of ($s*) or 
        all of ($b*) or 
        all of ($c*) or 
        $magic
}


