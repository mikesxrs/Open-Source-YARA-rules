rule Lightweight_Backdoor

{
    meta:
		author = "US CERT"
		reference = "https://www.us-cert.gov/ncas/alerts/TA14-353A"

    strings:
	    $STR1 = "NetMgStart"
		$STR2 = "Netmgmt.srg"

	condition:
    	(uint16(0) == 0x5A4D) and all of them
        }