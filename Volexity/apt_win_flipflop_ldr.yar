
rule apt_win_flipflop_ldr : APT29
{
    meta:
        author = "threatintel@volexity.com"
        date = "2021-05-25"
        description = "A loader for the CobaltStrike malware family, which ultimately takes the first and second bytes of an embedded file, and flips them prior to executing the resulting payload."
        reference = "https://www.volexity.com/blog/2021/05/27/suspected-apt29-operation-launches-election-fraud-themed-phishing-campaigns/"
        hash = "ee42ddacbd202008bcc1312e548e1d9ac670dd3d86c999606a3a01d464a2a330" 
        license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"

    strings:
        $s1 = "irnjadle"
        $s2 = "BADCFEHGJILKNMPORQTSVUXWZY"
        $s3 = "iMrcsofo taBesC yrtpgoarhpciP orived r1v0."

    condition:
        all of ($s*)
}
