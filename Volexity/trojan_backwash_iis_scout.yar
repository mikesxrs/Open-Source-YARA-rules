rule trojan_backwash_iis_scout : XEGroup
{
    meta:
        author = "threatintel@volexity.com"
        description = "Simple backdoor which collects information about the IIS server it is installed on. It appears to the attacker refers to this components as 'XValidate' - i.e. to validate infected machines."
        reference = "https://www.volexity.com/blog/2021/12/07/xe-group-exposed-8-years-of-hacking-card-skimming-for-profit/"
        date = "2021-11-17"
        hash1 = "6f44a9c13459533a1f3e0b0e698820611a18113c851f763797090b8be64fd9d5"
        memory_suitable = 1
        license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"

    strings:
        $s1 = "SOAPRequest" ascii
        $s2 = "requestServer" ascii
        $s3 = "getFiles" ascii
        $s4 = "APP_POOL_CONFIG" wide
        $s5 = "<virtualDirectory" wide
        $s6 = "stringinstr" ascii
        $s7 = "504f5354" wide
        $s8 = "XValidate" ascii
        $s9 = "XEReverseShell" ascii
        $s10 = "XERsvData" ascii

    condition:
        6 of them
}


