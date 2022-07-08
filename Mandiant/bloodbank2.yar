rule FE_APT_Tool_Linux_BLOODBANK_2 
{ 
    meta: 
        author = "Mandiant"  
        date_created = "2021-05-17" 
        sha256 = "8bd504ac5fb342d3533fbe0febe7de5c2adcf74a13942c073de6a9db810f9936" 
        reference_url = "https://www.fireeye.com/blog/threat-research/2021/05/updates-on-chinese-apt-compromising-pulse-secure-vpn-devices.html"  
    strings: 
        $ss1 = "\x00:%4d-%02d-%02d %02d:%02d:%02d  \x00" 
        $ss2 = "\x00ok!\x00" 
        $ss3 = "\x00\x0a\x0a%s:%s   \x00" 
        $ss4 = "\x00PRIMARY!%s   \x00" 
    condition: 
        (uint32(0) == 0x464c457f) and all of them 
}