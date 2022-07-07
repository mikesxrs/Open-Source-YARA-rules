rule trojan_win_backwash_cpp : XEGroup
{
    meta:
        author = "threatintel@volexity.com"
        description = "CPP loader for the Backwash malware."
        reference = "https://www.volexity.com/blog/2021/12/07/xe-group-exposed-8-years-of-hacking-card-skimming-for-profit/"
        date = "2021-11-17"
        hash1 = "0cf93de64aa4dba6cec99aa5989fc9c5049bc46ca5f3cb327b49d62f3646a852"
        memory_suitable = 1
        license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"

    strings:
        $s1 = "cor1dbg.dll" wide
        $s2 = "XEReverseShell.exe" wide
        $s3 = "XOJUMAN=" wide
        
    condition:
        2 of them
}
