rule APT32_ActiveMime_Lure{
	meta:
		filetype = "MIME entity"
		author = "Ian Ahl (@TekDefense) and Nick Carr (@ItsReallyNick)"
		date = "2017-03-02"
		description = "Developed to detect APT32 (OceanLotus Group phishing lures used to target Fireeye Customers in 2016 and 2017"
		reference = "https://www.fireeye.com/blog/threat-research/2017/05/cyber-espionage-apt32.html"
	strings:
		$a1 = "office_text" wide ascii
		$a2 = "schtasks /create /tn" wide ascii
		$a3 = "scrobj.dll" wide ascii
		$a4 = "new-object net.webclient" wide ascii
		$a5 = "GetUserName" wide ascii
		$a6 = "WSHnet.UserDomain" wide ascii
		$a7 = "WSHnet.UserName" wide ascii
	condition:
		4 of them
}
