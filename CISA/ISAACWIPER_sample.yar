rule CISA_10376640_01 : trojan wiper ISAACWIPER
{
   meta:
       Author = "CISA Code & Media Analysis"
       Incident = "10376640"
       Date = "2022-03-14"
       Last_Modified = "20220418_1900"
       Actor = "n/a"
       Category = "Trojan Wiper"
       Family = "ISAACWIPER"
       Description = "Detects ISACC Wiper samples"
       Reference = "https://www.cisa.gov/uscert/ncas/analysis-reports/ar22-115b"
       MD5_1 = "aa98b92e3320af7a1639de1bac6c17cc"
       SHA256_1 = "abf9adf2c2c21c1e8bd69975dfccb5ca53060d8e1e7271a5e9ef3b56a7e54d9f"
       MD5_2 = "8061889aaebd955ba6fb493abe7a4de1"
       SHA256_2 = "afe1f2768e57573757039a40ac40f3c7471bb084599613b3402b1e9958e0d27a"
       MD5_3 = "ecce8845921a91854ab34bff2623151e"
       SHA256_3 = "13037b749aa4b1eda538fda26d6ac41c8f7b1d02d83f47b0d187dd645154e033"
   strings:
       $s0 = { 73 00 74 00 61 00 72 00 74 00 20 00 65 00 72 00 61 00 73 00 69 00 6E 00 67 }
       $s1 = { 6C 00 6F 00 67 00 69 00 63 00 61 00 6C }
       $s2 = { 46 00 41 00 49 00 4C 00 45 00 44 }
       $s3 = { 5C 00 6C 00 6F 00 67 00 2E 00 74 00 78 00 74 }
       $s4 = { 69 73 20 70 72 6F 67 72 61 6D 20 63 61 6E 6E 6F }
       $s5 = {53 74 61 72 74 40 34}
       $s6 = {3B 57 34 74 2D 6A}
       $s7 = {43 6C 65 61 6E 65 72 2E}
   condition:
       all of ($s0,$s1,$s2,$s3,$s4) or all of ($s5,$s6,$s7)
}
