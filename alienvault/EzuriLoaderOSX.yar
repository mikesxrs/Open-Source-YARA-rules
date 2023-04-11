rule EzuriLoaderOSX : OSXMalware {
    meta:
        author = "AT&T Alien Labs"
        type = "malware"
        description = "Detects Ezuri Golang loader."
        copyright = "AT&T Cybersecurity 2020"
        reference = "da5ae0f2a4b6a52d483fb006bc9e9128"
        report = "https://cybersecurity.att.com/blogs/labs-research/malware-using-new-ezuri-memory-loader"
    strings:
        $a1 = "ezuri/stub/main.go"
        $a2 = "main.runFromMemory"
        $a3 = "main.aesDec"
        $Go = "go.buildid"
    condition:
        (uint32(0) == 0xfeedface or   
        uint32(0) == 0xcefaedfe or   
        uint32(0) == 0xfeedfacf or
        uint32(0) == 0xcffaedfe or    
        uint32(0) == 0xcafebabe or   
        uint32(0) == 0xbebafeca)
        and $Go and filesize < 5MB and all of ($a*)
}
