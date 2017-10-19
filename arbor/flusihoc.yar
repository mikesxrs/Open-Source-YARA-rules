rule flusihoc 
{
	meta:
		author = "tnelson@arbor.net"
    company = "Arbor Networks"
    reference = "https://www.arbornetworks.com/blog/asert/the-flusihoc-dynasty-a-long-standing-ddos-botnet/"
		date = "2017-07-06"
		description = "Chinese DDoS Bot related to Expleror"
		filetype = "exe"
		md50 = "7c04cef7061ecff84f50fbfa4f568611"
		md51 = "a81d8ed447170b930e89e482781393f6"
		md52 = "e6454373c877dfddcd5297b0049a58f8"
	
	strings:
		$ddos0 = "GET %s%s%s%s%s%s%s%s%s%s"
		$ddos1 = "%s|%s|%s|%s|%send"
		$info0 = "HARDWARE\\DESCRIPTION\\System\\CentralProcessor\\0"
		$info1 = "~MHz"
		$info2 = "%d*%dMHz"
		$cmd0 = "SYN_Flood"
		$cmd1 = "UDP_Flood"
		$cmd2 = "ICMP_Flood"
		$cmd3 = "TCP_Flood"
		$cmd4 = "HTTP_Flood"
		$cmd5 = "DNS_Flood"
		$cmd6 = "CON_Flood"
		$cmd7 = "CC_Flood"
		$cmd8 = "CC_Flood2"
		$pdb0 = "C:\\Users\\chengzhen\\Desktop\\"
		$pdb1 = "\\svchost\\Release\\svchost.pdb"
		$status0 = "null"
		$status1 = "Idle"
		$status2 = "Busy"
		$status3 = "RSDS"

	condition:
		(uint16(0) == 0x5A4D) and (2 of ($ddos*,$status*)) and (all of ($info*, $cmd*)) and (any of ($pdb*))
}
