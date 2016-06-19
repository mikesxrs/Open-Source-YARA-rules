rule blackenergy3_api_encode
{
    meta:
        author = "Mike Schladt"
        date = "2015-06-08"
        description = "matches api name encoding function for be3 persistence dll"
        md5 = "46649163C659CBA8A7D0D4075329EFA3"
        reference  = "https://www.f-secure.com/documents/996508/1030745/blackenergy_whitepaper.pdf"
        
    strings:
        $api_encode = {8B C2 C1 E8 09 32 E0 32 C4 32 E0 0F C8 66 8B CA 66 D1 E9 8A E1 33 C9 8A EA 66 D1 E9 8A C1 8B CA D1 E9 0F C9 0A C1 33 C9 8A 0B 33 C1 8B D0 43 EB CA}
        
    condition:
        $api_encode
        
}        

rule blackenergy3_push_bytes
{
    meta:
        author = "Mike Schladt"
        date = "2015-06-08"
        description = "matches push bytes used for api calls in be3 core files"
        md5 = "46649163C659CBA8A7D0D4075329EFA3"
        md5_2 = "78387651dd9608fcdf6bfb9df8b84db4"
        reference  = "https://www.f-secure.com/documents/996508/1030745/blackenergy_whitepaper.pdf"
        
    strings:        
        $push_4byte_1 = {68 EE EA C0 1F}
        $push_4byte_2 = {68 49 F3 A5 2C}
        $push_4byte_3 = {68 6B 43 59 4E}
        $push_4byte_4 = {68 E6 4B 59 4E}
        $push_4byte_5 = {68 6C 91 BA 4F}
        $push_4byte_6 = {68 8A 86 39 56}
        $push_4byte_7 = {68 9E 6D BD 5C}
        $push_4byte_8 = {68 FE 6A 7A 69}
        $push_4byte_9 = {68 A1 B0 5C 72}
        $push_4byte_10 = {68 60 A2 8A 76}
        $push_4byte_11 = {68 67 95 CD 77}
        $push_4byte_12 = {68 EB 3D 03 84}
        $push_4byte_13 = {68 19 2B 90 95}
        $push_4byte_14 = {68 62 67 8D A4}
        $push_4byte_15 = {68 AF 02 91 AB}
        $push_4byte_16 = {68 26 80 AC C8}
    
    condition:
        all of them
    
}