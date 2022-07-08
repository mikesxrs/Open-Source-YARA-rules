rule trojan_any_pupyrat_b : Commodity
{
    meta:
        author = "threatintel@volexity.com"
        description = "Detects the PUPYRAT malware family, a cross-platform RAT written in Python."
        date = "2022-04-07"
        hash1 = "7474a6008b99e45686678f216af7d6357bb70a054c6d9b05e1817c8d80d536b4"
        reference = "https://github.com/n1nj4sec/pupy"
        reference2 = "https://www.volexity.com/blog/2022/06/15/driftingcloud-zero-day-sophos-firewall-exploitation-and-an-insidious-breach/"
        license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"
        memory_suitable = 1

    strings:
        $elf1 = "LD_PRELOAD=%s HOOK_EXIT=%d CLEANUP=%d exec %s 1>/dev/null 2>/dev/null" ascii
        $elf2 = "reflective_inject_dll" fullword ascii
        $elf3 = "ld_preload_inject_dll" fullword ascii
        
        $pupy1 = "_pupy.error" ascii
        $pupy2 = "_pupy" ascii
        $pupy3 = "pupy://" ascii
        
        $s1 = "Args not passed" ascii
        $s2 = "Too many args" ascii
        $s3 = "Can't execute" ascii
        $s4 = "mexec:stdin" ascii
        $s5 = "mexec:stdout" ascii
        $s6 = "mexec:stderr" ascii
        $s7 = "LZMA error" ascii


    condition:
        any of ($elf*) or 
        all of ($pupy*) or 
        all of ($s*)
}
