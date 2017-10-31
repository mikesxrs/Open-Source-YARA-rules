rule spora_pki : malware
{
    meta:
        description = "Identify Spora PKI"
        author = "tracker [_at] h3x.eu"

    strings:
        $spora_key1_1 = "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC6COfj49E0yjEopSpP5kbeCRQp"
        $spora_key1_2 = "WdpWvx5XJj5zThtBa7svs/RvX4ZPGyOG0DtbGNbLswOYKuRcRnWfW5897B8xWgD2"
        $spora_key1_3 = "AMQd4KGIeTHjsbkcSt1DUye/Qsu0jn4ZB7yKTEzKWeSyon5XmYwoFsh34ueErnNL"
        $spora_key1_4 = "LZQcL88hoRHo0TVqAwIDAQAB"

    condition:
         //file_type contains "MZ"
        uint16(0) == 0x5a4d
        and all of ( $spora_key1_* )
}
