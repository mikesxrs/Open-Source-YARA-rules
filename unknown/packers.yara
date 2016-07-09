// 
// This rules are based on PEiD signatures (http://www.peid.info/BobSoft/Downloads/UserDB.zip)
// 

rule ASPack
{
        strings: 
        $ = { 60 E8 ?? ?? ?? ?? 5D 81 ED ?? ?? (43 | 44) ?? B8 ?? ?? (43 | 44) ?? 03 C5 }
        $ = { 60 EB ?? 5D EB ?? FF ?? ?? ?? ?? ?? E9 }
        $ = { 60 EB 03 5D FF E5 E8 F8 FF FF FF 81 ED 1B 6A 44 00 BB 10 6A 44 00 03 DD 2B 9D 2A }
        $ = { 60 E8 00 00 00 00 5D ?? ?? ?? ?? ?? ?? BB ?? ?? ?? ?? 03 DD }
        $ = { 60 E8 41 06 00 00 EB 41 }
        $ = { 60 E8 7? 05 00 00 EB (33 | 4C) }
        $ = { 60 E8 02 00 00 00 EB 09 5D 55 }
        $ = { 60 E8 03 00 00 00 E9 EB 04 5D 45 55 C3 E8 01 }
        $ = { A8 03 ?? ?? 61 75 08 B8 01 ?? ?? ?? C2 0C ?? 68 ?? ?? ?? ?? C3 8B 85 26 04 ?? ?? 8D 8D 3B 04 ?? ?? 51 50 FF 95 }          

        condition:
        
            for any of them : ($ at entrypoint)
}


rule Armadillo
{
    strings: 
        $ = { 83 7C 24 08 01 75 05 E8 DE 4B 00 00 FF 74 24 04 8B 4C 24 10 8B 54 24 0C E8 ED FE FF FF 59 C2 0C 00 6A 0C 68 ?? ?? ?? ?? E8 } 
        $ = { E8 ?? ?? 00 00 E9 16 FE FF FF 6A 0C 68 ?? ?? ?? ?? E8 ?? ?? 00 00 8B 4D 08 33 FF 3B CF 76 2E 6A E0 58 33 D2 F7 F1 3B 45 0C }
        $ = { E8 ?? ?? 00 00 E9 16 FE FF FF 6A 0C 68 ?? ?? ?? ?? E8 ?? ?? 00 00 83 65 E4 00 8B 75 08 3B 35 ?? ?? ?? ?? 77 22 6A 04 E8 ?? ?? 00 00 }
        $ = { 55 8B EC 53 8B 5D 08 56 8B 75 0C 57 8B 7D 10 85 F6 }
        $ = { 55 8B EC 6A FF 68 ?? ?? ?? ?? (68 | E0 | B0 | 40) ?? ?? ?? ?? (64 A1 | 68) }
        $ = { 6A ?? 8B B5 ?? ?? ?? ?? C1 E6 04 8B 85 ?? ?? ?? ?? 25 07 ?? ?? 80 79 05 48 83 C8 F8 40 33 C9 8A 88 ?? ?? ?? ?? 8B 95 }
        $ = { 60 E8 ?? ?? ?? ?? 5D 50 51 ?? ?? ?? ?? ?? ?? ?? ?? ?? EB 0F ?? EB ?? ?? EB ?? ?? EB }  
        $ = { 44 64 65 44 61 74 61 20 69 6E 69 74 69 61 6C 69 7A 65 64 20 28 41 4E 53 49 29 2C 20 61 70 70 20 73 74 72 69 6E 67 73 20 61 72 65 20 27 25 73 }
        $ = { 31 2E 31 2E 34 00 00 00 C2 E0 94 BE 93 FC DE C6 B6 24 83 F7 D2 A4 92 77 40 27 CF EB D8 6F 50 B4 B5 29 24 FA 45 08 04 52 D5 1B D2 8C 8A 1E 6E }

    condition:
    
        any of them             
}


rule FSG
{
    strings: 
        $noep1  = { 0B D0 8B DA E8 02 00 00 00 40 A0 5A EB 01 9D B8 80 ?? ?? ?? EB 02 CD 20 03 D3 8D 35 F4 00 }
        $noep2  = { 33 D2 0F BE D2 EB 01 C7 EB 01 D8 8D 05 80 ?? ?? ?? EB 02 CD 20 EB 01 F8 BE F4 00 00 00 EB }
        $noep3  = { 33 C2 2C FB 8D 3D 7E 45 B4 80 E8 02 00 00 00 8A 45 58 68 02 ?? 8C 7F EB 02 CD 20 5E 80 C9 }
        $noep4  = { 80 E9 A1 C1 C1 13 68 E4 16 75 46 C1 C1 05 5E EB 01 9D 68 64 86 37 46 EB 02 8C E0 5F F7 D0 }
        $noep5  = { BE A4 01 40 00 AD 93 AD 97 AD 56 96 B2 80 A4 B6 80 FF 13 73 }    
        $noep6  = { E8 01 00 00 00 0E 59 E8 01 00 00 00 58 58 BE 80 ?? ?? 00 EB 02 61 E9 68 F4 00 00 00 C1 C8 }
        $noep7  = { E8 01 00 00 00 5A 5E E8 02 00 00 00 BA DD 5E 03 F2 EB 01 64 BB 80 ?? ?? 00 8B FA EB 01 A8 }
        $noep8  = { EB 01 DB E8 02 00 00 00 86 43 5E 8D 1D D0 75 CF 83 C1 EE 1D 68 50 ?? 8F 83 EB 02 3D 0F 5A }
        $noep9  = { EB 01 56 E8 02 00 00 00 B2 D9 59 68 80 ?? 41 00 E8 02 00 00 00 65 32 59 5E EB 02 CD 20 BB }
        $noep10 = { EB 01 4D 83 F6 4C 68 80 ?? ?? 00 EB 02 CD 20 5B EB 01 23 68 48 1C 2B 3A E8 02 00 00 00 38 }
        $noep11 = { EB 02 AB 35 EB 02 B5 C6 8D 05 80 ?? ?? 00 C1 C2 11 BE F4 00 00 00 F7 DB F7 DB 0F BE 38 E8 }
        $noep12 = { EB 02 CD 20 2B C8 68 80 ?? ?? 00 EB 02 1E BB 5E EB 02 CD 20 68 B1 2B 6E 37 40 5B 0F B6 C9 }
        $noep13 = { EB 02 CD 20 EB 02 CD 20 EB 02 CD 20 C1 E6 18 BB 80 ?? ?? 00 EB 02 82 B8 EB 01 10 8D 05 F4 }
        $noep14 = { EB 02 09 94 0F B7 FF 68 80 ?? ?? 00 81 F6 8E 00 00 00 5B EB 02 11 C2 8D 05 F4 00 00 00 47 }
        $noep15 = { 23 CA EB 02 5A 0D E8 02 00 00 00 6A 35 58 C1 C9 10 BE 80 ?? ?? 00 0F B6 C9 EB 02 CD 20 BB }
        $noep16 = { 2B C2 E8 02 00 00 00 95 4A 59 8D 3D 52 F1 2A E8 C1 C8 1C BE 2E ?? ?? 18 EB 02 AB A0 03 F7 }
        $noep17 = { 1B DB E8 02 00 00 00 1A 0D 5B 68 80 ?? ?? 00 E8 01 00 00 00 EA 5A 58 EB 02 CD 20 68 F4 00 }
        $noep18 = { 03 DE EB 01 F8 B8 80 ?? 42 00 EB 02 CD 20 68 17 A0 B3 AB EB 01 E8 59 0F B6 DB 68 0B A1 B3 }
        $noep19 = { 03 F7 23 FE 33 FB EB 02 CD 20 BB 80 ?? 40 00 EB 01 86 EB 01 90 B8 F4 00 00 00 83 EE 05 2B }
        $noep21 = { C1 CB 10 EB 01 0F B9 03 74 F6 EE 0F B6 D3 8D 05 83 ?? ?? EF 80 F3 F6 2B C1 EB 01 DE 68 77 }
        $noep22 = { C1 C8 10 EB 01 0F BF 03 74 66 77 C1 E9 1D 68 83 ?? ?? 77 EB 02 CD 20 5E EB 02 CD 20 2B F7 }
        $noep23 = { 2C 71 1B CA EB 01 2A EB 01 65 8D 35 80 ?? ?? 00 80 C9 84 80 C9 68 BB F4 00 00 00 EB 01 EB }
        $noep24 = { F7 D8 40 49 EB 02 E0 0A 8D 35 80 ?? ?? ?? 0F B6 C2 EB 01 9C 8D 1D F4 00 00 00 EB 01 3C 80 }
        $noep25 = { F7 D0 EB 02 CD 20 BE BB 74 1C FB EB 02 CD 20 BF 3B ?? ?? FB C1 C1 03 33 F7 EB 02 CD 20 68 }
        $noep26 = { F7 DB 80 EA BF B9 2F 40 67 BA EB 01 01 68 AF ?? ?? BA 80 EA 9D 58 C1 C2 09 2B C1 8B D7 68 }
        $noep27 = { F7 D8 0F BE C2 BE 80 ?? ?? 00 0F BE C9 BF 08 3B 65 07 EB 02 D8 29 BB EC C5 9A F8 EB 01 94 }
        $noep28 = { 91 EB 02 CD 20 BF 50 BC 04 6F 91 BE D0 ?? ?? 6F EB 02 CD 20 2B F7 EB 02 F0 46 8D 1D F4 00 }
        $noep29 = { C1 CE 10 C1 F6 0F 68 00 ?? ?? 00 2B FA 5B 23 F9 8D 15 80 ?? ?? 00 E8 01 00 00 00 B6 5E 0B }
        $noep30 = { C1 F0 07 EB 02 CD 20 BE 80 ?? ?? 00 1B C6 8D 1D F4 00 00 00 0F B6 06 EB 02 CD 20 8A 16 0F }
        $noep31 = { C1 E0 06 EB 02 CD 20 EB 01 27 EB 01 24 BE 80 ?? 42 00 49 EB 01 99 8D 1D F4 00 00 00 EB 01 }
        $noep32 = { D1 E9 03 C0 68 80 ?? ?? 00 EB 02 CD 20 5E 40 BB F4 00 00 00 33 CA 2B C7 0F B6 16 EB 01 3E }
        $noep33 = { EB 02 CD 20 EB 01 91 8D 35 80 ?? ?? 00 33 C2 68 83 93 7E 7D 0C A4 5B 23 C3 68 77 93 7E 7D }
        $noep34 = { 4B 45 52 4E 45 4C 33 32 2E 64 6C 6C 00 00 4C 6F 61 64 4C 69 62 72 61 72 79 41 00 00 47 65 }
        $noep35 = { 0F BE C1 EB 01 0E 8D 35 C3 BE B6 22 F7 D1 68 43 ?? ?? 22 EB 02 B5 15 5F C1 F1 15 33 F7 80 }
        $noep36 = { 0F B6 D0 E8 01 00 00 00 0C 5A B8 80 ?? ?? 00 EB 02 00 DE 8D 35 F4 00 00 00 F7 D2 EB 02 0E }
        $noep37 = { 87 FE E8 02 00 00 00 98 CC 5F BB 80 ?? ?? 00 EB 02 CD 20 68 F4 00 00 00 E8 01 00 00 00 E3 } 
        
        $ep1 = { BB D0 01 40 ?? BF ?? 10 40 ?? BE }
        $ep2 = { EB 01 ?? EB 02 ?? ?? ?? 80 ?? ?? 00 }
        $ep3 = { BB D0 01 40 ?? BF ?? 10 40 ?? BE }
        $ep4 = { EB 01 ?? EB 02 ?? ?? ?? 80 ?? ?? 00 }
        $ep5 = { BE ?? ?? ?? 00 BF ?? ?? ?? 00 BB ?? ?? ?? 00 53 BB ?? ?? ?? 00 B2 80 }
        $ep6 = { EB 02 CD 20 03 ?? 8D ?? 80 ?? ?? 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? EB 02 }
        $ep7 = { EB 02 CD 20 ?? CF ?? ?? 80 ?? ?? 00 ?? ?? ?? ?? ?? ?? ?? ?? 00 }
        $ep8 = { 87 25 ?? ?? ?? ?? 61 94 55 A4 B6 80 FF 13 }     

    condition:
    
        any of ($noep*) or for any of ($ep*) : ($ at entrypoint)     
}


rule UPX 
{
    strings:
    
        $noep1 = { B8 ?? ?? ?? ?? B9 ?? ?? ?? ?? 33 D2 EB 01 0F 56 EB 01 0F E8 03 00 00 00 EB 01 0F EB 01 0F 5E EB 01 }
        $noep2 = { 5E 89 F7 B9 ?? ?? ?? ?? 8A 07 47 2C E8 3C 01 77 F7 80 3F ?? 75 F2 8B 07 8A 5F 04 66 C1 E8 08 C1 C0 10 86 C4 29 F8 80 EB E8 01 F0 89 07 83 C7 }
        $noep3 = { 01 DB [0-1] 07 8B 1E 83 EE FC 11 DB [1-4] B8 01 00 00 00 01 DB }
        $noep4 = { 9C 60 E8 00 00 00 00 5D B8 B3 85 40 00 2D AC 85 40 00 2B E8 8D B5 D5 FE FF FF 8B 06 83 F8 00 74 11 8D B5 E1 FE FF FF 8B 06 83 F8 01 0F 84 F1 }
        $noep5 = { 8A 06 46 88 07 47 01 DB 75 07 8B 1E 83 EE FC 11 DB }
        $noep6 = { FF D5 80 A7 ?? ?? ?? ?? ?? 58 50 54 50 53 57 FF D5 58 61 8D 44 24 ?? 6A 00 39 C4 75 FA 83 EC 80 E9 }
        $noep7 = { 55 FF 96 ?? ?? ?? ?? 09 C0 74 07 89 03 83 C3 04 EB ?? FF 96 ?? ?? ?? ?? 8B AE ?? ?? ?? ?? 8D BE 00 F0 FF FF BB 00 10 00 00 50 54 6A 04 53 57 }
        $noep8 = { FF D5 8D 87 ?? ?? ?? ?? 80 20 ?? 80 60 ?? ?? 58 50 54 50 53 57 FF D5 58 61 8D 44 24 ?? 6A 00 39 C4 75 FA 83 EC 80 E9 }

        $ep1 = { 60 E8 00 00 00 00 58 83 E8 3D }
        $ep2 = { 60 E8 00 00 00 00 83 CD FF 31 DB 5E }
        $ep3 = { 50 BE ?? ?? ?? ?? 8D BE ?? ?? ?? ?? 57 83 CD }
        
    condition:
    
        any of ($noep*) or for any of ($ep*) : ($ at entrypoint)
}

