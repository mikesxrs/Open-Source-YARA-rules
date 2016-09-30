rule TrojanVirtoolObfuscator
{
		meta:
			Description = "Trojan.Obfuscator.rc"
			ThreatLevel = "5"
			
		strings:
			$ = "1346243623461" ascii wide
			$ = "3nterface" ascii wide
		condition:
			all of them
}