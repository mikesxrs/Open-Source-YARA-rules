rule MS12_052
{
        meta:
                author = "Adnan Mohd Shukor" 
                author_email = "adnan.shukor @ G!"
                ref = "MS12-052"
                ref_url = "http://seclists.org/bugtraq/2012/Sep/29"
                cve = "CVE-"
                version = "1"
                impact = 4
                hide = false
        strings:
                $ms12052_1 = /mailto\:.{2000,}/ nocase fullword
                $ms12052_2 = /\.getElements?By/ nocase
                $ms12052_3 = /\.removeChild\(/ nocase
                //$ms12052_4 = /document\..*?= ?null/ nocase *greedy and ungreedy quantifiers can't be mixed in a regular expression*
        condition:
                $ms12052_1 and $ms12052_2 and ($ms12052_3 /*or $ms12052_4*/)
}
