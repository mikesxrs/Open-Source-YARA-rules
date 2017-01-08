rule dridex : dridex
{
	meta:
		description = “Dridex Malware Indicators”
		author = “Kunal Makwana”
		date = “2016/04/03”
		thread_level = 4
		in_the_wild = true

	strings:
		$domain = “g-t-c-co.uk” nocase
		$ip = “185.11.240.14” wide ascii
		$mail = “ali73_2008027@yahoo.co.uk” wide ascii

	condition:
		$domain or $ip or $mail
}
