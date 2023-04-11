rule EzuriLoader : LinuxMalware {
    meta:
        author = "AT&T Alien Labs"
        type = "malware"
        description = "Detects Ezuri Golang loader."
        copyright = "AT&T Cybersecurity 2020"
        reference = "283e0172063d1a23c20c6bca1ed0d2bb"
        report = "https://cybersecurity.att.com/blogs/labs-research/malware-using-new-ezuri-memory-loader"
    strings:
        $a1 = "ezuri/stub/main.go"
        $a2 = "main.runFromMemory"
        $a3 = "main.aesDec"
    condition:
        uint32(0) == 0x464c457f and
        filesize < 20MB and all of ($a*)
}
