rule MTI_Hunting_INDUSTROYERv2_Strings {

    meta:

        author = "Mandiant"

        date = "04-09-2022"

        description = "Searching for executables containing strings associated with the INDUSTROYER.V2 malware family."
        
        reference = "https://www.mandiant.com/resources/industroyer-v2-old-malware-new-tricks"


    strings:

        $a1 = "M%X - %02d:%02d:%02d" nocase ascii wide

        $a2 = "%02hu:%02hu:%02hu:%04hu" nocase ascii wide

        $a3 = "%s M%X " nocase ascii wide

        $a4 = "%s: %d: %d" nocase ascii wide

        $a5 = "%s M%X %d (%s)" nocase ascii wide

        $a6 = "%s M%X SGCNT %d" nocase ascii wide

        $a7 = "%s ST%X %d" nocase ascii wide

        $a8 = "Current operation : %s" nocase ascii wide

        $a9 = "Sent=x%X | Received=x%X" nocase ascii wide

        $a10 = "ASDU:%u | OA:%u | IOA:%u | " nocase ascii wide

        $a11 = "Cause: %s (x%X) | Telegram type: %s (x%X" nocase ascii wide

 

        $b1 = "Length:%u bytes | " nocase ascii wide

        $b2 = "Unknown APDU format !!!" nocase ascii wide

        $b3 = "MSTR ->> SLV" nocase ascii wide

        $b4 = "MSTR <<- SLV" nocase ascii wide

 

    condition:

        filesize < 3MB and

        uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550 and

        (1 of ($a*) and 1 of ($b*))

}
