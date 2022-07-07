rule CISA_10376640_02 : trojan wiper worm HERMETICWIZARD
{
   meta:
       Author = "CISA Code & Media Analysis"
       Incident = "10376640"
       Date = "2022-03-12"
       Last_Modified = "20220413_1300"
       Actor = "n/a"
       Category = "Trojan Wiper Worm"
       Family = "HERMETICWIZARD"
       Description = "Detects Hermetic Wizard samples"
       Reference = "https://www.cisa.gov/uscert/ncas/analysis-reports/ar22-115b"
       MD5_1 = "0959bf541d52b6e2915420442bf44ce8"
       SHA256_1 = "5a300f72e221a228e3a36a043bef878b570529a7abc15559513ea07ae280bb48"
   strings:
       $s0 = { 70 00 69 00 70 00 65 00 5C 00 25 00 73 }
       $s1 = { 6E 00 6D 00 61 00 6E 00 73 00 65 00 72 00 76 }
       $s2 = { 73 61 6D 72 }
       $s3 = { 62 72 6F 77 73 65 72 }
       $s4 = { 6E 65 74 6C 6F 67 6F 6E }
       $s5 = { 6C 73 61 72 70 63 }
       $s6 = { 6E 74 73 76 63 73 }
       $s7 = { 73 76 63 63 74 6C }
       $s8 = { 73 74 61 72 74 20 63 6D 64 20 2F 63 20 22 70 69 6E 67 20 6C 6F 63 61 6C 68 6F 73 74 }
       $s9 = { 67 00 75 00 65 00 73 00 74 }
       $s10 = { 74 00 65 00 73 00 74 }
       $s11 = { 75 00 73 00 65 00 72 }
       $s12 = { 61 00 64 00 6D 00 69 00 6E 00 69 00 73 00 74 00 72 00 61 00 74 00 6F }
       $s13 = { 51 00 61 00 7A 00 31 00 32 00 33 }
       $s14 = { 51 00 77 00 65 00 72 00 74 00 79 00 31 00 32 }
       $s15 = { 63 6D 64 20 2F 63 20 73 74 61 72 74 20 72 65 67 }
   condition:
       all of them
}
