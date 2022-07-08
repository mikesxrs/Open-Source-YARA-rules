rule M_APT_Downloader_BEATDROP

{

    meta:

        author = "Mandiant"

        description = "Rule looking for BEATDROP malware"
        
        reference = "https://www.mandiant.com/resources/tracking-apt29-phishing-campaigns"

    strings:

        $ntdll1 = "ntdll" ascii fullword

        $ntdll2 = "C:\\Windows\\System32\\ntdll.dll" ascii fullword nocase

        $url1 = "api.trello.com" ascii

        $url2 = "/members/me/boards?key=" ascii

        $url3 = "/cards?key=" ascii

    condition:

        uint16(0) == 0x5a4d and uint32(uint32(0x3C)) == 0x00004550 and filesize < 1MB and all of them

}

