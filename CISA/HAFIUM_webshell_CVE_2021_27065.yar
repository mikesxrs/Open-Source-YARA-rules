rule CISA_10328929_01 : trojan webshell exploit CVE_2021_27065
{
   meta:
       Author = "CISA Code & Media Analysis"
       Incident = "10328929"
       Date = "2021-03-17"
       Last_Modified = "20210317_2200"
       Actor = "n/a"
       Category = "Trojan WebShell Exploit CVE-2021-27065"
       Family = "HAFNIUM"
       Description = "Detects CVE-2021-27065 Webshellz"
       Reference = "https://www.cisa.gov/uscert/ncas/analysis-reports/ar21-084b"
       MD5_1 = "ab3963337cf24dc2ade6406f11901e1f"
       SHA256_1 = "c8a7b5ffcf23c7a334bb093dda19635ec06ca81f6196325bb2d811716c90f3c5"
   strings:
       $s0 = { 65 76 61 6C 28 52 65 71 75 65 73 74 5B 22 [1-32] 5D 2C 22 75 6E 73 61 66 65 22 29 }
       $s1 = { 65 76 61 6C 28 }
       $s2 = { 28 52 65 71 75 65 73 74 2E 49 74 65 6D 5B [1-36] 5D 29 29 2C 22 75 6E 73 61 66 65 22 29 }
       $s3 = { 49 4F 2E 53 74 72 65 61 6D 57 72 69 74 65 72 28 52 65 71 75 65 73 74 2E 46 6F 72 6D 5B [1-24] 5D }
       $s4 = { 57 72 69 74 65 28 52 65 71 75 65 73 74 2E 46 6F 72 6D 5B [1-24] 5D }
   condition:
       $s0 or ($s1 and $s2) or ($s3 and $s4)
}
