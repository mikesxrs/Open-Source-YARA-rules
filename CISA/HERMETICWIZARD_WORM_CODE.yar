rule CISA_10376640_05 : trojan wiper worm HERMETICWIZARD
{
   meta:
       Author = "CISA Code & Media Analysis"
       Incident = "10376640"
       Date = "2022-04-14"
       Last_Modified = "20220414_1037"
       Actor = "n/a"
       Category = "Trojan Wiper Worm"
       Family = "HERMETICWIZARD"
       Description = "Detects Hermetic Wizard samples"
       Reference = "https://www.cisa.gov/uscert/ncas/analysis-reports/ar22-115b"
       MD5_1 = "517d2b385b846d6ea13b75b8adceb061"
       SHA256 = "a259e9b0acf375a8bef8dbc27a8a1996ee02a56889cba07ef58c49185ab033ec"
   strings:
       $s0 = { 57 69 7A 61 72 64 2E 64 6C 6C }
       $s1 = { 69 6E 66 6C 61 74 65 }
       $s2 = { 4D 61 72 6B 20 41 64 6C 65 72 }
   condition:
       all of them and filesize < 2000KB
}
