rule MTI_Hunting_INDUSTROYERv2_Bytes {

    meta:

        author = "Mandiant"

        date = "04-09-2022"

        description = "Searching for executables containing bytecode associated with the INDUSTROYER.V2 malware family."
        
        reference = "https://www.mandiant.com/resources/industroyer-v2-old-malware-new-tricks"

   

    strings:

        $bytes = {8B [2] 89 [2] 8B 0D [4] 89 [2] 8B 15 [4] 89 [2] A1 [4] 89 [2] 8B 0D [4] 89 [2] 8A 15 [4] 88 [2] 8D [2] 5? 8B [2] E8}

   

    condition:

        filesize < 3MB and

        uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550 and

        $bytes

}
