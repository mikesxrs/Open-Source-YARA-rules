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