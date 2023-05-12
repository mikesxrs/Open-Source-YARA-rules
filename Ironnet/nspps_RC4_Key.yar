rule nspps_RC4_Key {
    meta:
        author = "IronNet Threat Research"
        date = "20200320"
        version = "1.0.0"
        description = "RC4 Key used in nspps RAT"
        reference = "SHA1:3bbb58a2803c27bb5de47ac33c6f13a9b8a5fd79"
        report = "https://www.ironnet.com/blog/malware-analysis-nspps-a-go-rat-backdoor"
    strings:
        $s1 = { 37 36 34 31 35 33 34 34 36 62 36 31 }
    condition:
        all of them
}
