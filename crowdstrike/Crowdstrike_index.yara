rule CrowdStrike_PutterPanda_01 : fourh_stack_strings putterpanda
	{
	meta:
		description = "PUTTER PANDA - 4H RAT"
                author = "CrowdStrike"
		date = "2014-03-30"
		version = "1.0"
		in_the_wild = true
		copyright = "CrowdStrike, Inc."
		actor = "PUTTER PANDA"
		yara_version = ">=1.6"
	
	strings:
	    $key_combined_1 = { C6 44 24 ?? 34 C6 44 24 ?? 36 C6 44 24 ?? 21 C6 44 24 ?? 79 C6 44 24 ?? 6F C6 44 24 ?? 00 }
	
	
	    // ebp
	    $keyfrag_ebp_1 = { C6 45 ?? 6C }    // ld66!yo
	    $keyfrag_ebp_2 = { C6 45 ?? 64 } 
	    $keyfrag_ebp_3 = { C6 45 ?? 34 }
	    $keyfrag_ebp_4 = { C6 45 ?? 36 }
	    $keyfrag_ebp_5 = { C6 45 ?? 21 }
	    $keyfrag_ebp_6 = { C6 45 ?? 79 }
	    $keyfrag_ebp_7 = { C6 45 ?? 6F }
	
	    // esp
	    $keyfrag_esp_1 = { c6 44 ?? 6C }    // ld66!yo
	    $keyfrag_esp_2 = { c6 44 ?? 64 }
	    $keyfrag_esp_3 = { c6 44 ?? 34 }
	    $keyfrag_esp_4 = { c6 44 ?? 36 }
	    $keyfrag_esp_5 = { c6 44 ?? 21 }
	    $keyfrag_esp_6 = { c6 44 ?? 79 }
	    $keyfrag_esp_7 = { c6 44 ?? 6F }
	
	    // reduce FPs by checking for some common strings
	    $check_zeroes = "0000000"
	    $check_param = "Invalid parameter"
	    $check_ercv = "ercv= %d"
	    $check_unk = "unknown"
	
	condition:
	    any of ($key_combined*) or 
	    (1 of ($check_*) and
	        (
	            (
	                all of ($keyfrag_ebp_*) and
	                for any i in (1..#keyfrag_ebp_5) : (
	                    for all of ($keyfrag_ebp_*): ($ in (@keyfrag_ebp_5[i]-100..@keyfrag_ebp_5[i]+100))
	                )
	            )
	            or
	            (
	                for any i in (1..#keyfrag_esp_5) : (
	                    for all of ($keyfrag_esp_*): ($ in (@keyfrag_esp_5[i]-100..@keyfrag_esp_5[i]+100))
	                )
	            )
	        )
	    )
	}
    
rule CrowdStrike_PutterPanda_02 : rc4_dropper putterpanda
	{
	meta:
		description = "PUTTER PANDA - RC4 dropper"
		date = "2014-03-30"
		version = "1.0"
		in_the_wild = true
		copyright = "CrowdStrike, Inc."
		actor = "PUTTER PANDA"
	
	strings:
	    $res_lock = "LockResource"
	    $res_size = "SizeofResource"
	    $res_load = "LoadResource"
	
	    $com = "COMSPEC"
	
	    //$stack_h = { C6 4? [1-2] 68 }    
	    //$stack_o = { C6 4? [1-2] 6F }
	    //$stack_v = { C6 4? [1-2] 76 }
	    //$stack_c = { C6 4? [1-2] 63 }
	    //$stack_x = { C6 4? [1-2] 78 }
	    //$stack_dot = { C6 4? [1-2] 2E }
	
	    $cryptaq = "CryptAcquireContextA"
	
	condition:
	    uint16(0) == 0x5A4D and
	    (all of ($res_*)) and 
	    /*(all of ($stack_*)) and*/
	    $cryptaq and $com
	}
	
rule CrowdStrike_PutterPanda_03 : threepara_para_implant putterpanda
	{
	meta:
		description = "PUTTER PANDA - 3PARA RAT"
		date = "2014-03-30"
		version = "1.0"
		in_the_wild = true
		copyright = "CrowdStrike, Inc."
		actor = "PUTTER PANDA"
	
	strings:
	    $parafmt        = "%s%dpara1=%dpara2=%dpara3=%d"
	    $class_attribe  = "CCommandAttribe"
	    $class_cd       = "CCommandCD"
	    $class_cmd      = "CCommandCMD"
	    $class_nop      = "CCommandNop"
	
	condition:
	    $parafmt or all of ($class_*)
	}
	
	rule CrowdStrike_PutterPanda_04: pngdowner putterpanda
	{
	meta:
		description = "PUTTER PANDA - PNGDOWNER"
		date = "2014-03-30"
		version = "1.0"
		in_the_wild = true
		copyright = "CrowdStrike, Inc."
		actor = "PUTTER PANDA"
	
	strings:
	    $myagent = "myAgent"
	    $readfile = "read file error:"
	    $downfile = "down file success"
	    $avail = "Avaliable data:%u bytes"
	
	condition:
	    3 of them
	}

rule CrowdStrike_PutterPanda_05 : httpclient putterpanda
	{
	meta:
		description = "PUTTER PANDA - HTTPCLIENT"
		date = "2014-03-30"
		version = "1.0"
		in_the_wild = true
		copyright = "CrowdStrike, Inc."
		actor = "PUTTER PANDA"
	
	strings:
	    $recv_wrong = "Error:recv worng"
	
	condition:
	    any of them
	}
    
rule CrowdStrike_PutterPanda_06 : xor_dropper putterpanda
	{
	meta:
		description = "PUTTER PANDA - XOR based dropper"
		date = "2014-03-30"
		version = "1.0"
		in_the_wild = true
		copyright = "CrowdStrike, Inc."
		actor = "PUTTER PANDA"
	
	strings:
	    $xorloop = { 8b d0 83 e2 0f 8a 54 14 04 30 14 01 83 c0 01 3b c6 7c ed  }
	
	condition:
	    $xorloop
	}
    
rule CrowdStrike_CSIT_14003_03 : installer 

{ 

       meta: 

             copyright = "CrowdStrike, Inc" 

             description = "Flying Kitten Installer" 

             version = "1.0" 

             actor = "FLYING KITTEN" 

             in_the_wild = true 

             reference = "http://www.crowdstrike.com/blog/cat-scratch-fever-crowdstrike-tracks-newly-reported-iranian-actor-flying-kitten/"

       strings: 

             $exename = "IntelRapidStart.exe" 

             $confname = "IntelRapidStart.exe.config" 

             $cabhdr = { 4d 53 43 46 00 00 00 00 } 

       condition: 

             all of them 

}

rule CrowdStrike_FlyingKitten : rat
{
meta: 

            copyright = "CrowdStrike, Inc" 

             description = "Flying Kitten RAT" 

             version = "1.0" 

             actor = "FLYING KITTEN" 

             in_the_wild = true 

       strings: 

             $classpath = "Stealer.Properties.Resources.resources" 

             //$pdbstr = "\Stealer\obj\x86\Release\Stealer.pdb" 

       condition: 

             all of them and 

             uint16(0) == 0x5A4D and uint32(uint32(0x3c)) == 0x4550 and 

             uint16(uint32(0x3C) + 0x16) & 0x2000 == 0 and 

             ((uint16(uint32(0x3c)+24) == 0x010b and 

            uint32(uint32(0x3c)+232) > 0) or 

             (uint16(uint32(0x3c)+24) == 0x020b and 

            uint32(uint32(0x3c)+248) > 0)) 

} 

/*

//error with rule no $i

rule CrowdStrike_P2P_Zeus
{
    meta:
        copyright = "CrowdStrike, Inc"
	author = "Crowdstrike, Inc"
        description = "P2P Zeus (Gameover)"
        version = "1.0"
        last_modified = "2013-11-21"
        actor = "Gameover Spider"
        malware_family = "P2P Zeus"
        in_the_wild = true
        
    condition:
        any of them or
        for any i in (0..filesize) :
        (
            uint32(i) ^ uint32(i+4) == 0x00002606
            and uint32(i) ^ uint32(i+8) == 0x31415154
            and uint32(i) ^ uint32(i+12) == 0x00000a06
            and uint32(i) ^ uint32(i+16) == 0x00010207
            and uint32(i) ^ uint32(i+20) == 0x7cf1aa2d
            and uint32(i) ^ uint32(i+24) == 0x4390ca7b
            and uint32(i) ^ uint32(i+28) == 0xa96afd9d
            and uint32(i) ^ uint32(i+32) == 0x0b039138
            and uint32(i) ^ uint32(i+36) == 0xb3e50578
            and uint32(i) ^ uint32(i+40) == 0x896eaf36
            and uint32(i) ^ uint32(i+44) == 0x37a3f8c9
            and uint32(i) ^ uint32(i+48) == 0xb1c31bcb
            and uint32(i) ^ uint32(i+52) == 0xcb58f22c
            and uint32(i) ^ uint32(i+56) == 0x00491be8
            and uint32(i) ^ uint32(i+60) == 0x0a2a748f
        )
}

*/

rule CrowdStrike_CVE_2014_4113 {
meta:
	copyright = "CrowdStrike, Inc"
	description = "CVE-2014-4113 Microsoft Windows x64 Local Privilege Escalation Exploit"
	version = "1.0"
	last_modified = "2014-10-14"
	in_the_wild = true
strings:
	$const1 = { fb ff ff ff }
	$const2 = { 0b 00 00 00 01 00 00 00 }
	$const3 = { 25 00 00 00 01 00 00 00 }
	$const4 = { 8b 00 00 00 01 00 00 00 }
condition:
	all of them
}