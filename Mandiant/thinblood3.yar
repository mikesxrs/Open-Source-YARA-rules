rule FE_APT_Tool_Linux32_THINBLOOD_1
{
    meta:
        author = "Mandiant" 
        date_created = "2021-04-16"
        sha256 = "88170125598a4fb801102ad56494a773895059ac8550a983fdd2ef429653f079"
        reference_url = "https://www.fireeye.com/blog/threat-research/2021/04/suspected-apt-actors-leverage-bypass-techniques-pulse-secure-zero-day.html"
    strings:
        $sb1 = { E8 [4-32] 8? 10 [0-16] 89 ?? 24 04 89 04 24 E8 [4-32] 8B 00 89 04 24 E8 [4] E8 [4-32] C7 44 24 ?? 6D 76 20 00 [0-32] F3 AB [0-32] C7 44 24 ?? 72 6D 20 00 [0-32] F3 AB [0-32] 89 04 24 E8 [4-32] 89 04 24 E8 [4-32] 89 04 24 E8 [4-32] 89 04 24 E8 [4-16] 89 04 24 E8 }
    condition:
        ((uint32(0) == 0x464c457f) and (uint8(4) == 1)) and all of them
}