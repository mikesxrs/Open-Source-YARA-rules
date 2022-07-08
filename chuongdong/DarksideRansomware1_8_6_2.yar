rule DarksideRansomware1_8_6_2 {
  meta:
    description = "YARA rule for Darkside v1.8.6.2"
    reference = "http://chuongdong.com/reverse%20engineering/2021/05/06/DarksideRansomware/"
    author = "@cPeterr"
    tlp = "white"
  strings:
    $hash_alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
    $gen_key_buff = {89 54 0E 0C 89 44 0E 08 89 5C 0E 04 89 3C 0E 81 EA 10 10 10 10 2D 10 10 10 10 81 EB  10 10 10 10 81 EF 10 10 10 10 83 E9 10 79 D5}
    $dyn_api_resolve = {FF 76 FC 56 E8 91 FE FF FF 56 E8 ?? 69 00 00 8B D8 FF 76 FC 56 E8 85 FB FF FF 8B 46 FC 8D 34 06 B9 23 00 00 00 E8 5E 02 00 00 AD}
    $get_config_len = {81 3C 18 DE AD BE EF 75 02 EB 03 40 EB F2}
    $RSA_1024_add_big_num = {8B 06 8B 5E 04 8B 4E  08 8B 56 0C 11 07 11 5F 04 11 4F 08 11 57 0C}
    $CRC32_checksum = {FF 75 0C FF 75 08 68 EF BE AD DE FF 15 ?? ?? ?? 00 FF 75 0C FF 75 08 50 FF 15 ?? ?? ?? 00 31 07 FF 75 0C FF 75 08 50 FF 15 ?? ?? ?? 00 }
  condition:
    all of them
}
