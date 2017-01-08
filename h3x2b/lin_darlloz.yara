rule darlloz__payload: malware linux worm
{
        meta:
                author = "@h3x2b <tracker@h3x.eu>"
                description = "Detects darlloz samples - 20161102"
                //Check also:
                // https://www.symantec.com/security_response/writeup.jsp?docid=2013-112710-1612-99&tabid=2
                // 
                //Samples:

        strings:
		$x_01 = "/var/run/.zollard/"
		$x_02 = "/kernel/net/ipv4/netfilter/ip_tables.ko"
		$x_03 = "/kernel/net/ipv4/netfilter/iptable_filter.ko"
		$x_04 = "telnetd"
		$x_05 = "/var/run/.lightpid"
		$x_06 = "/var/run/.aidrapid"
		$x_07 = "/var/run/lightpid"

        condition:
                //ELF magic
                uint32(0) == 0x464c457f and

                //Contains all of the specific strings
                all of ( $x_* ) 
}
