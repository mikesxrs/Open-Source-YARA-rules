rule NK_GOLDBACKDOOR_Main
{
meta:
author= "Silas Cutler"
description = "Detection for Main component of GOLDBACKDOOR"
reference = "https://stairwell.com/news/threat-research-the-ink-stained-trail-of-goldbackdoor/"
version = "0.1"
strings:
$str1 = "could not exec bash command." wide
$str2 = "%userprofile%\\AppData" wide
$str3 = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/90.0.3112.113 Safari/537.36" wide
$str4 = "tickount: %d"
$str5 = "Service-0x" wide
$str6 = "Main Returned"
$b64_1 = "TwBuAGUARAByAHYAVQBwAGQAYQB0AGUAAAA="
$b64_2 = "aGFnZW50dHJheQ=="
$b64_3 = "YXBwbGljYXRpb24vdm5kLmdvb2dsZS1hcHBzLmZvbGRlcg=="
$pdb = "D:\\Development\\GOLD-BACKDOOR\\"
condition:
4 of them or ( $pdb and 1 of them )
}
