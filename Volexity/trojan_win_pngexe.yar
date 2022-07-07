import "pe"
rule trojan_win_pngexe : XEGroup
{
    meta:
        author = "threatintel@volexity.com"
        date = "2020-09-04"
        description = "Detects PNGEXE, a simple reverse shell loader."
        reference = "https://www.volexity.com/blog/2021/12/07/xe-group-exposed-8-years-of-hacking-card-skimming-for-profit/"
        hash = "72f7d4d3b9d2e406fa781176bd93e8deee0fb1598b67587e1928455b66b73911"
        hash2 = "4d913ecb91bf32fd828d2153342f5462ae6b84c1a5f256107efc88747f7ba16c"
        memory_suitable = 0
        license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"

    strings:
        $a1 = "amd64.png" ascii
        $a2 = "x86.png" ascii
        
    condition:
    	uint16(0) == 0x5A4D and 
        (
        	(
                any of ($a*) and 
                filesize > 30KB and 
                filesize < 200KB
            ) or   
          pe.imphash() == "ca41f83b03cf3bb51082dbd72e3ba1ba" or 
          pe.imphash() == "e93abc400902e72707edef1f717805f0" or 
          pe.imphash() == "83a5d4aa20a8aca2a9aa6fc2a0aa30b0"
         )
}

