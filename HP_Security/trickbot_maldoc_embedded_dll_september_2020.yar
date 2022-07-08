rule trickbot_maldoc_embedded_dll_september_2020 {
    meta:
        author = "HP-Bromium Threat Research"
        reference = "https://threatresearch.ext.hp.com/detecting-a-stealthy-trickbot-campaign/"
        date = "2020-10-03"
        sharing = "TLP:WHITE"

    strings:
        $magic = { D0 CF 11 E0 A1 B1 1A E1 }
        $s1 = "EncryptedPackage" wide
        $s2 = "{FF9A3F03-56EF-4613-BDD5-5A41C1D07246}" wide
        $s3 = { FF FF FF FF FF FF FF FF FF FF ( 90 90 | 10 10 | E2 E2 | 17 17 ) FF FF FF FF FF FF FF FF FF FF }

    condition:
        $magic at 0 and
        all of ($s*) and
        (filesize > 500KB and filesize < 1000KB)
}
