rule XSLCMD
{
	meta:
    	Author = "mikesxrs"
    	Description = "Looking for unique code"
	    Reference = "https://totalhash.cymru.com/analysis/?46bb20aefd09ea0bad534d3aa9b567d89b5ae8c4"
        Reference2 = "https://www.fireeye.com/blog/threat-research/2014/09/forced-to-adapt-xslcmd-backdoor-now-on-os-x.html"
        md5 = "60242ad3e1b6c4d417d4dfeb8fb464a1"
    strings:
    	$STR1 = "<!-- begin"
        $STR2 = "end -->"
        $STR3 = "12TUNNEL_ERROR"
        $STR4 = "Mozilla/5.0 (Macintosh; U; Mac OS X) Safari/532.5 X_MAC("
        
        $CMD1 = "[End Time]"
        $CMD2 = "[FakeDomain]"
        $CMD3 = "[ListenMode]"
        $CMD4 = "[MServer]"
        $CMD5 = "[MWeb]"
        $CMD6 = "[MWebTrans]"
        $CMD7 = "[Proxy]"
        $CMD8 = "[SPACE]"
        $CMD9 = "[Start Time]"
        $CMD10 = "[Interval]"
        $CMD11 = "[Update]"
        $CMD12 = "[UpdateWeb]"
    condition:
        (uint32(0) == 0xfeedface 
        or uint32(0) == 0xcefaedfe 
        or uint32(0) == 0xfeedfacf 
        or uint32(0) == 0xcffaedfe 
        or uint32(0) == 0xcafebabe 
        or uint32(0) == 0xbebafeca)
        and all of ($STR*) and 5 of ($CMD*)
}
