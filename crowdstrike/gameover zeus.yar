/*

//error with rule no $i

rule CrowdStrike_P2P_Zeus
{
    meta:
        copyright = "CrowdStrike, Inc"
    author = "Crowdstrike, Inc"
        description = "P2P Zeus (Gameover)"
        version = "1.0"
        last_modified = "2013-11-21"
        actor = "Gameover Spider"
        malware_family = "P2P Zeus"
        in_the_wild = true
        
    condition:
        any of them or
        for any i in (0..filesize) :
        (
            uint32(i) ^ uint32(i+4) == 0x00002606
            and uint32(i) ^ uint32(i+8) == 0x31415154
            and uint32(i) ^ uint32(i+12) == 0x00000a06
            and uint32(i) ^ uint32(i+16) == 0x00010207
            and uint32(i) ^ uint32(i+20) == 0x7cf1aa2d
            and uint32(i) ^ uint32(i+24) == 0x4390ca7b
            and uint32(i) ^ uint32(i+28) == 0xa96afd9d
            and uint32(i) ^ uint32(i+32) == 0x0b039138
            and uint32(i) ^ uint32(i+36) == 0xb3e50578
            and uint32(i) ^ uint32(i+40) == 0x896eaf36
            and uint32(i) ^ uint32(i+44) == 0x37a3f8c9
            and uint32(i) ^ uint32(i+48) == 0xb1c31bcb
            and uint32(i) ^ uint32(i+52) == 0xcb58f22c
            and uint32(i) ^ uint32(i+56) == 0x00491be8
            and uint32(i) ^ uint32(i+60) == 0x0a2a748f
        )
}

*/