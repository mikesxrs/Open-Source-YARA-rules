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