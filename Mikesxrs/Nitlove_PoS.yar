rule Nitlove_PoS
{
	meta:
    	Author = "@X0RC1SM"
        Description = "Looking for uniques strings from reports"
        Reference1 = "https://www.fireeye.com/blog/threat-research/2015/05/nitlovepos_another.html"
		Reference2 = "https://securingtomorrow.mcafee.com/mcafee-labs/evoltin-pos-malware-attacks-via-macro/"
        Date = "2017-10-28"
    strings:
    	$STR1 = "nit_love"
		  $STR2 = "derpos/gateway.php"
    condition:
        any of them
}
