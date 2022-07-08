rule win_l0rdix {
	meta:
		author = "Alex Holland (Bromium Labs)"
        reference = "https://threatresearch.ext.hp.com/an-analysis-of-l0rdix-rat-panel-and-builder/"
		date = "2019-07-19"
		sample_1 = "18C6AAF76985404A276466D73A89AC5B1652F8E9659473F5D6D656CA2705B0D3"
		sample_2 = "C2A4D706D713937F47951D4E6E975754C137159DC2C30715D03331FC515AE4E8"
		
	strings:
		$ua = "Mozilla/5.0 (Windows NT 10.0; WOW64; rv:53.0) Gecko/20100101 Firefox/53.0" wide // Firefox 53 on Windows 10
		$sig = "L0rdix" wide ascii
		$sched_task = "ApplicationUpdateCallback" wide
		$exe = "syscall.exe" wide
		$cnc_url_1 = "connect.php?" wide
		$cnc_url_2 = "show.php" wide 
		$browser_1 = "\\Kometa\\User Data\\Default\\Cookies" wide 
		$browser_2 = "\\Orbitum\\User Data\\Default\\Cookies" wide
		$browser_3 = "\\Amigo\\User\\User Data\\Default\\Cookies" wide
		$coin_regex_1 = "[13][a-km-zA-HJ-NP-Z1-9]{25,34}" wide // Bitcoin
		$coin_regex_2 = "0x[a-fA-F0-9]{40}" wide // Ethereum
		$coin_regex_3 = "L[a-zA-Z0-9]{26,33}" wide // Litecoin
		
	condition:
		uint16(0) == 0x5A4D and (any of ($ua,$sig,$sched_task,$exe)) and (any of ($cnc_url_*)) and (any of ($browser_*)) and (any of ($coin_regex_*))
}
