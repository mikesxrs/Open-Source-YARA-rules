rule CISA_10376640_04 : trojan wiper CADDYWIPER
{
   meta:
       Author = "CISA Code & Media Analysis"
       Incident = "10376640"
       Date = "2022-03-23"
       Last_Modified = "20220324_1700"
       Actor = "n/a"
       Category = "Trojan Wiper"
       Family = "CADDYWIPER"
       Description = "Detects Caddy wiper samples"
       Reference = "https://www.cisa.gov/uscert/ncas/analysis-reports/ar22-115c"
       MD5_1 = "42e52b8daf63e6e26c3aa91e7e971492"
       SHA256_1 = "a294620543334a721a2ae8eaaf9680a0786f4b9a216d75b55cfd28f39e9430ea"
   strings:
       $s0 = { 44 73 52 6F 6C 65 47 65 74 50 72 69 6D 61 72 79 44 6F 6D 61 69 6E }
       $s1 = { 50 C6 45 A1 00 C6 45 A2 48 C6 45 A3 00 C6 45 A4 59 C6 }
       $s2 = { C6 45 A6 53 C6 45 A7 00 C6 45 A8 49 C6 }
       $s3 = { C6 45 B0 44 C6 45 B1 00 C6 45 B2 52 }
       $s4 = { C6 45 B8 45 C6 45 B9 00 C6 45 BA 39 }
       $s5 = { C6 45 AC 43 C6 45 AD 3A C6 45 AE 5C C6 45 AF }
       $s6 = { 55 C6 45 B0 73 C6 45 B1 65 C6 45 B2 72 C6 45 B3 }
       $s7 = { C6 45 E0 44 C6 45 E1 3A C6 45 E2 5C C6 45 E3 }
       $s8 = { 21 54 68 69 73 20 70 72 6F 67 72 61 6D 20 63 61 6E 6E 6F }
   condition:
       all of them
}
