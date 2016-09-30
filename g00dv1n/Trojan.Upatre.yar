rule TrojanUpatreSample
{
    meta:
        Description = "Trojan.Upatre.vb"
        ThreatLevel = "5"

    strings:
        $hex_string = { 52 ba 6c 6c 00 00 52 ba 73 66 2e 64 52 ba 32 5c 71 61 52 ba 74 65 6d 33 52 ba 5c 73 79 73 52}

    condition:
        $hex_string
}