rule Gh0stRAT
{
meta:
    author = "@abhinavbom"
    maltype = "NA"
    version = "0.1"
    date = "21/09/2015"
    description = "rule for Gh0stRAT 3.6 variant June 2015"
    originalauthor = "John Petrequin (jpetrequin@wapacklabs.com)"
    ref1 = "http://researchcenter.paloaltonetworks.com/2015/09/musical-chairs-multi-year-campaign-involving-new-variant-of-gh0st-malware/"
    ref2= "1d7cb7250cf14ed2b9e1c99facba55df"
strings:
    $MZ = "MZ"
    $a = "piano.dll"
    $b1 = "Programed by Zhou Zhangfa" wide
    $b2 = "Please check your Sound Galaxy card." wide
condition:
    $MZ and $a and any of ($b*)
}