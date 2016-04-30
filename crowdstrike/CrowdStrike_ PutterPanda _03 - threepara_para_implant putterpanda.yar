rule CrowdStrike_ PutterPanda _03 : threepara_para_implant putterpanda
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
	
	rule CrowdStrike_ PutterPanda _04: pngdowner putterpanda
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