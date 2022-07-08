rule Mal_Backdoor_ChaChi_RAT
{
            meta:
                        description = "ChaChi RAT used in PYSA Ransomware Campaigns"
                        reference = "https://blogs.blackberry.com/en/2021/06/pysa-loves-chachi-a-new-golang-rat"
                        author = "BlackBerry Threat Research & Intelligence"            

            strings:
                        // "Go build ID:"
                        $go = { 47 6F 20 62 75 69 6C 64 20 49 44 3A }
                        // dnsStream
                        $dnsStream = { 64 6E 73 53 74 72 65 61 6D }
                        // SOCKS5
                        $socks5 = { 53 4F 43 4B 53 35 }
                        // chisel
                        $chisel = { 63 68 69 73 65 6C }                                   

            condition:
                        // MZ signature at offset 0
                        uint16(0) == 0x5A4D and
                        // PE signature at offset stored in MZ header at 0x3C
                        uint32(uint32(0x3C)) == 0x00004550 and
                        // ChaChi Strings
                        all of them
}
