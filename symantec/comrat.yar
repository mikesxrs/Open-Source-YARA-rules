rule comrat
{
	meta:
		author = "Symantec"
		malware = "COMRAT"		
        Reference="https://www.symantec.com/content/en/us/enterprise/media/security_response/whitepapers/waterbug-attack-group.pdf"

	strings:
		$mz = "MZ"
		$b = {C645????}
		$c = {C685??FEFFFF??}
		//$d = {FFA0??0?0000}
		$e = {89A8??00000068??00000056FFD78B}
		$f = {00004889????030000488B}
	
	condition:
		($mz at 0) and ((#c > 200 and #b > 200 ) /*or (#d > 40)*/ and (#e > 15 or #f > 30))
}