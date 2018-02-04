rule nymaim: trojan
{
    meta:
       author = "mak"
	   reference = "https://www.cert.pl/en/news/single/nymaim-revisited/"

    strings:
       $call_obfu_xor = {55 89 E5 5? 8B ?? 04 89 ?? 10 8B ?? 0C 33 ?? 08 E9 }
       $call_obfu_add = {55 89 E5 5? 8B ?? 04 89 ?? 10 8B ?? 0C 03 ?? 08 E9 }
       $call_obfu_sub = {55 89 E5 5? 8B ?? 04 89 ?? 10 8B ?? 0C 2b ?? 08 E9 }
       $nym_get_cnc = {E8 [4] C7 45 ?? [4] C7 45 ?? [4] 83 ??}//3D[4] 01 74 4E E8}
       $nym_get_cnc2 ={E8 [4] C7 45 ?? [4] 89 [5] 89 [5] C7 45 ?? [4] 83 ??}
       $nym_check_unp = {C7 45 ?? [4] 83 3D [3] 00 01 74 }
       $set_cfg_addr = {FF 75 ?? 8F 05 [4] FF 75 08 8F 05 [4] 68 [4] 5? 68 [4] 68 [4] E8}

    condition:
       (
            /* orig */
            (2 of ($call_obfu*)) and (
                /* old versions */
                $nym_check_unp or $nym_get_cnc2 or $nym_get_cnc or
                /* new version */
                $set_cfg_addr
            )
       )
}
