rule lyceum_dotnet_dns_backdoor
{
    meta:
        author = "CPR"
        reference = "https://research.checkpoint.com/2022/state-sponsored-attack-groups-capitalise-on-russia-ukraine-war-for-cyber-espionage/"
        hash1 = "8199f14502e80581000bd5b3bda250ee"
        hash2 = "d79687676d2d152aec4143c852bdbc4a"
        hash3 = "bcb465cc2257e5777bab431690ca5039"
        hash4 = "2bc2abefc1a721908bc805894b62227d"
        hash5 = "37a1514a7a5f9b2c6786096129a30721"
    strings:
        $log1 = "MSG SIZE rcvd" wide
        $log2 = "Empty output" wide
        $log3 = "Big Output. lines: " wide
        $com1 = "Enddd" wide
        $com2 = "uploaddd" wide
        $com3 = "downloaddd" wide
        $dga = "trailers.apple.com" wide
        $replace1 = "BackSlashh" wide
        $replace2 = "QuotationMarkk" wide
        $re_pattern = "60\\s+IN\\s+TXT" wide
        $func1 = "comRun"
        $func2 = "PlaceDot"
        $func3 = "sendAns"
        $heijden1 = "Heijden.DNS"
        $heijden2 = "DnsHeijden"
    condition:
        uint16(0)==0x5a4d and (all of ($log*) or all of ($com*) or all of ($replace*) or all of ($func*) or (any of ($heijden*) and $re_pattern and $dga))
}
