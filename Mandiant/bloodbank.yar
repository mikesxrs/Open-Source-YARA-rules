rule FE_APT_Tool_Linux32_BLOODBANK_1
{ 
    meta: 
        author = "Mandiant"  
        date_created = "2021-05-17" 
        sha256 = "8bd504ac5fb342d3533fbe0febe7de5c2adcf74a13942c073de6a9db810f9936" 
        reference_url = "https://www.fireeye.com/blog/threat-research/2021/05/updates-on-chinese-apt-compromising-pulse-secure-vpn-devices.html" 
    strings: 
        $sb1 = {0f b6 00 3c 75 [2-6] 8b 85 [4] 8d ?? 01 8b 85 [4] 01 ?? 0f b6 00 3c 73 [2-6] 8b 85 [4]  8d ?? 02 8b 85 [4] 01 ?? 0f b6 00 3c 65 [2-6] 8b 85 [4] 8d ?? 03 8b 85 [4] 01 ?? 0f b6 00 3c 72 [2-6] 8b 85 [4] 8d ?? 04 8b 85 [4] 01 ?? 0f b6 00 3c 40} 
        $sb2 = {0f b6 00 3c 70 [2-6] 8b 85 [4] 8d ?? 01 8b 85 [4] 01 ?? 0f b6 00 3c 61 [2-6] 8b 85 [4]  8d ?? 02 8b 85 [4] 01 ?? 0f b6 00 3c 73 [2-6] 8b 85 [4] 8d ?? 03 8b 85 [4] 01 ?? 0f b6 00 3c 73 [2-6] 8b 85 [4] 8d ?? 04 8b 85 [4] 01 ?? 0f b6 00 3c 77 [2-6] 8b 85 [4] 8d ?? 08 8b 85 [4] 01 ?? 0f b6 00 3c 40} 
        $ss1 = "\x00:%4d-%02d-%02d %02d:%02d:%02d  \x00" 
    condition: 
        ((uint32(0) == 0x464c457f) and (uint8(4) == 1)) and all of them 
}