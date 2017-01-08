rule torlus_20150112: malware linux
{
meta:
	author = "@h3x2b <tracker@h3x.eu>"
	description = "Detects Torlus/LizKebab/GayFgt/Bashdoor samples - 20150112"
	//Check also:
	//http://tracker.h3x.eu/corpus/690
	//http://tracker.h3x.eu/info/690
	//Samples:
	//https://github.com/gh0std4ncer/lizkebab/blob/master/client.c

strings:
	$cmd_00 = "PING"
	$cmd_01 = "GETLOCALIP"
	$cmd_02 = "SCANNER"
	$cmd_03 = "HOLD"
	$cmd_04 = "JUNK"
	$cmd_05 = "UDP"
	$cmd_06 = "TCP"
	$cmd_07 = "KILLATTK"
	$cmd_08 = "LOLNOGTFO"
	$cmd_09 = "EMAIL"

	$msg_01 = "MAC: %02X:%02X:%02X:%02X:%02X:%02X\n"
	$msg_02 = "Failed to connect...\n"
	$msg_03 = "Link closed by server.\n"
	$msg_04 = "REPORT %s:%s:"
	$msg_05 = "Failed opening raw socket."
	$msg_06 = "Failed setting raw headers mode."
	$msg_07 = "Invalid flag \"%s\""
	$msg_08 = "My IP: %s"
	$msg_09 = "EMAIL <target email> <mx host> <subject no spaces> <message no spaces>"
	$msg_10 = "HOLD <ip> <port> <time>"
	$msg_11 = "HOLD Flooding %s:%d for %d seconds."
	$msg_12 = "JUNK Flooding %s:%d for %d seconds."
	$msg_13 = "UDP Flooding %s for %d seconds."
	$msg_14 = "UDP Flooding %s:%d for %d seconds."
	$msg_15 = "TCP Flooding %s for %d seconds."
	$msg_16 = "Killed %d."
	$msg_17 = "None Killed."
	$msg_18 = "BUILD %s"
	$msg_19 = "BOGOMIPS"
	$msg_20 = "/proc/cpuinfo"

condition:
	//ELF magic
	uint32(0) == 0x464c457f and

	//Contains majority of commands
	8 of ($cmd_*) and

	//Contains some message strings
	10 of ($msg_*)

}


rule torlus_20161017: malware linux
{
meta:
	author = "@h3x2b <tracker@h3x.eu>"
	description = "Detects Torlus/LizKebab/GayFgt/Bashdoor samples - 20161017"
	//Check also:
	//http://tracker.h3x.eu/corpus/690
	//http://tracker.h3x.eu/info/690
	//https://github.com/gh0std4ncer/lizkebab/blob/master/client.c
	//Samples:
	//65e40f25a868a23e3cedf424b051eb9f  hxxp://146.0.79.229/1
	//2fb9ea2d48096808b01c7fabe4966a93  hxxp://146.0.79.229/2
	//dcf05749e6499a63bcd658ccce0b97f0  hxxp://146.0.79.229/3
	//db67599d4a7c1c5945f6f62f0333666c  hxxp://146.0.79.229/4
	//db67599d4a7c1c5945f6f62f0333666c  hxxp://146.0.79.229/5
	//5bbd98eb630b5c6400b17d204efdd62e  hxxp://146.0.79.229/6
	//af00a54311a78215c51874111971ec67  hxxp://146.0.79.229/7
	//a1fe71267f01e6bf7a7f6ba5cce72c6b  hxxp://146.0.79.229/8

strings:
	$cmd_00 = "PING"
	$cmd_01 = "GETLOCALIP"
	$cmd_02 = "SCANNER"
	$cmd_03 = "HOLD"
	$cmd_04 = "JUNK"
	$cmd_05 = "UDP"
	$cmd_06 = "COMBO"
	$cmd_07 = "TCP"
	$cmd_08 = "KILLATTK"
	$cmd_09 = "LOLNOGTFO"
	$cmd_10 = "GTFOFAG"
	$cmd_11 = "FATCOCK"

	$ua_01 = "Mozilla/5.0 (Windows; U; Windows NT 5.2; en-US; rv:1.9.1.3) Gecko/20090824 Firefox/3.5.3 (.NET CLR 3.5.30729)"
	$ua_02 = "Mozilla/5.0 (Windows; U; Windows NT 6.1; en-US; rv:1.9.1.1) Gecko/20090718 Firefox/3.5.1"
	$ua_03 = "Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US) AppleWebKit/532.1 (KHTML, like Gecko) Chrome/4.0.219.6 Safari/532.1"
	$ua_04 = "Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1; WOW64; Trident/4.0; SLCC2; .NET CLR 2.0.50727; InfoPath.2)"
	$ua_05 = "Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.0; Trident/4.0; SLCC1; .NET CLR 2.0.50727; .NET CLR 1.1.4322; .NET CLR 3.5.30729; .NET CLR 3.0.30729)"
	$ua_06 = "Mozilla/5.0 (Windows; U; Windows NT 5.2; en-US; rv:1.9.1.3) Gecko/20090824 Firefox/3.5.3 (.NET CLR 3.5.30729)"
	$ua_07 = "Mozilla/5.0 (Windows; U; Windows NT 6.1; en-US; rv:1.9.1.1) Gecko/20090718 Firefox/3.5.1"
	$ua_08 = "Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US) AppleWebKit/532.1 (KHTML, like Gecko) Chrome/4.0.219.6 Safari/532.1"
	$ua_09 = "Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1; WOW64; Trident/4.0; SLCC2; .NET CLR 2.0.50727; InfoPath.2)"
	$ua_10 = "Mozilla/5.0 (Windows; U; MSIE 7.0; Windows NT 6.0; en-US)"
	$ua_11 = "Mozilla/4.0 (compatible; MSIE 6.1; Windows XP)"
	$ua_12 = "Opera/9.80 (Windows NT 5.2; U; ru) Presto/2.5.22 Version/10.51"

	$msg_01 = "ogin:"
	$msg_02 = "assword:"
	$msg_03 = "ncorrect"
	$msg_04 = "HTTP"
	$msg_05 = "REPORT %s:%s:%s"
	$msg_06 = "Failed opening raw socket."
	$msg_07 = "Failed setting raw headers mode."
	$msg_08 = "Invalid flag \"%s\""
	$msg_09 = "My IP: %s"
	$msg_10 = "BUILD %s"
	$msg_11 = "BOGOMIPS"
	$msg_12 = "/proc/cpuinfo"

	$shell_01 = "rm -rf /var/log/wtmp"
	$shell_02 = "rm -rf /tmp/*"
	$shell_03 = "history -c"
	$shell_04 = "rm -rf ~/.bash_history"
	$shell_05 = "rm -rf /bin/netstat"
	$shell_06 = "service iptables stop"

condition:
	//ELF magic
	uint32(0) == 0x464c457f and

	//Contains majority of commands
	8 of ($cmd_*) and

	//Contains at least 5 UA strings
	5 of ($ua_*) and

	//Contains some message strings
	6 of ($msg_*) and

	//Shell commands used to clean-up
	3 of ($shell_*)

}


rule torlus_server: malware linux
{
meta:
	author = "@h3x2b <tracker@h3x.eu>"
	description = "Detects Torlus/LizKebab/GayFgt/Bashdoor server samples"
	//Check also:
	//http://tracker.h3x.eu/corpus/690
	//http://tracker.h3x.eu/info/690
	//Samples:
	//https://github.com/gh0std4ncer/lizkebab/blob/master/client.c

strings:
	$cmd_00 = "PING"
	$cmd_01 = "PONG"
	$cmd_02 = "BUILD"
	$cmd_03 = "REPORT"

	$msg_01 = "!* SCANNER ON\n"
	$msg_02 = "!* FATCOCK\n"
	$msg_03 = "buf: \"%s\"\n"
	$msg_04 = "%c]0;Bots connected: %d | Clients connected: %d%c"
	$msg_05 = "WELCOME TO THE BALL PIT"



condition:
	//ELF magic
	uint32(0) == 0x464c457f and

	//Contains majority of commands
	4 of ($cmd_*) and

	//Contains some message strings
	2 of ($msg_*)

}



