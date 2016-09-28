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