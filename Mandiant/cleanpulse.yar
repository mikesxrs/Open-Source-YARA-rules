rule FE_APT_Tool_Linux32_CLEANPULSE_1 
{ 
    meta: 
        author = "Mandiant"  
        date_created = "2021-05-17" 
        sha256 = "9308cfbd697e4bf76fcc8ff71429fbdfe375441e8c8c10519b6a73a776801ba7" 
        reference_url = "https://www.fireeye.com/blog/threat-research/2021/05/updates-on-chinese-apt-compromising-pulse-secure-vpn-devices.html" 
    strings: 
        $sb1 = { A1 [4] 8B [5] 50 68 [4] 5? FF 75 ?? E8 [4] 83 C4 10 A1 [4] 8B [5] 50 68 [4] 5? FF 75 ?? E8 [4] 83 C4 10 A1 [4] 8B [5] 50 68 [4] 5? FF 75 ?? E8 [4] 83 C4 10 A1 [4] 8B [5] 50 68 [4] 5? FF 75 ?? E8 [4] 83 C4 10 8B ?? 04 } 
        $sb2 = { 8B 00 0F B6 00 3C ?? 74 0F 8B ?? 04 83 C0 10 8B 00 0F B6 00 3C ?? 75 } 
        $ss1 = "\x00OK!\x00" 
        $ss2 = "\x00argv %d error!\x00" 
        $ss3 = "\x00ptrace_write\x00" 
        $ss4 = "\x00ptrace_attach\x00" 
    condition: 
        ((uint32(0) == 0x464c457f) and (uint8(4) == 1)) and all of them 
} 