

rule android_meterpreter
{
    meta:
        author="73mp74710n"
        comment="Metasploit Android Meterpreter Payload"
        
    strings:
	$checkPK = "META-INF/PK"
	$checkHp = "[Hp^"
	$checkSdeEncode = /;.Sk/
	$stopEval = "eval"
	$stopBase64 = "base64_decode"
	
    condition:
	any of ($check*) or any of ($stop*)
}

global rule isExecutable
{
	meta:
		author="73mp74710n"
		description="Yara rule to check for unobfuscated rat created with njrat"
	strings: 
		$MZ = { 4D 5A 90 00 }
		$PE = { 50 45 00 00 }
	condition:
		$MZ at 0 and $PE
	
}

/*

rule njRat  
{
	
	strings:
		$firewallDelete = "firewall delete allowed " wide
		$firewallAdded = "firewall add" wide

		/*ftw, ping ??*/
	/*	$ping = "ping" wide 

		/*regular expressoin to match an ip address*/
	/*	$regularExp = /([0-9]{1,3}\.){3}[0-9]{1,3}/ wide
		
	condition:
		 any of ($firewall*) or $ping or $regularExp 
		
}

*/