rule DarkComet
{
	strings:
	    $a1 = "#BOT#"
	    $a2 = "WEBCAMSTOP"
	    $a3 = "UnActiveOnlineKeyStrokes"
	    $a4 = "#SendTaskMgr"
	    $a5 = "#RemoteScreenSize"
	    $a6 = "ping 127.0.0.1 -n 4 > NUL &&"
	condition:
		all of them
}
