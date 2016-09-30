rule BackdoorZegostSampleA
{
        meta:
			Description  = "Backdoor.Zegost.rc"
			ThreatLevel  = "5"

        strings:
            $a = "VIPBlackDDOS" ascii wide
			$b = "SynFlood" ascii wide
			$c = "ICMPFlood" ascii wide
			$d = "UDPFlood" ascii wide
			$e = "DNSFlood" ascii wide
			$f = "Game2Flood" ascii wide
			$g = "HTTPGetFlood" ascii wide
        condition:
            2 of them
}