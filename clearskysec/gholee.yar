 rule gholee

    {

    meta:

    author = "www.clearskysec.com"

    date = "2014/08"

    maltype = "Remote Access Trojan"

    filetype = "dll"

    reference = "http://www.clearskysec.com/gholee-a-protective-edge-themed-spear-phishing-campaign/"


    strings:

    $a = "sandbox_avg10_vc9_SP1_2011"

    $b = "gholee"

    condition:

    all of them

    }