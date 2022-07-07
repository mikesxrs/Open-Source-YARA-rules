rule trojan_win_cobaltstrike : Commodity
{
    meta:
        author = "threatintel@volexity.com"
        date = "2021-05-25"
        description = "The CobaltStrike malware family."
        reference = "https://www.volexity.com/blog/2021/05/27/suspected-apt29-operation-launches-election-fraud-themed-phishing-campaigns/"
        hash = "b041efb8ba2a88a3d172f480efa098d72eef13e42af6aa5fb838e6ccab500a7c"
        license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"

    strings:
        $s1 = "%s (admin)" fullword
        $s2 = {48 54 54 50 2F 31 2E 31 20 32 30 30 20 4F 4B 0D 0A 43 6F 6E 74 65 6E 74 2D 54 79 70 65 3A 20 61 70 70 6C 69 63 61 74 69 6F 6E 2F 6F 63 74 65 74 2D 73 74 72 65 61 6D 0D 0A 43 6F 6E 74 65 6E 74 2D 4C 65 6E 67 74 68 3A 20 25 64 0D 0A 0D 0A 00}
        $s3 = "%02d/%02d/%02d %02d:%02d:%02d" fullword
        $s4 = "%s as %s\\%s: %d" fullword
        $s5 = "%s&%s=%s" fullword
        $s6 = "rijndael" fullword
        $s7 = "(null)"

    condition:
        all of them
}
