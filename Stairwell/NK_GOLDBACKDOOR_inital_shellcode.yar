rule NK_GOLDBACKDOOR_inital_shellcode
{
meta:
author= "Silas Cutler (silas@Stairwell.com)"
description = "Detection for initial shellcode loader used to deploy GOLDBACDOOR"
reference = "https://stairwell.com/news/threat-research-the-ink-stained-trail-of-goldbackdoor/"
version = "0.1"
strings:
//seg000:07600058 8D 85 70 FE FF FF lea eax, [ebp+var_190]
//seg000:0760005E C7 45 C4 25 6C 6F 63 mov dword ptr [ebp+var_3C],'col%'
//seg000:07600065 50 push eax
//...
//seg000:0760008F C7 45 D8 6F 6C 64 2E mov dword ptr [ebp+var_3C+14h], '.dlo'
//seg000:07600096 C7 45 DC 74 78 74 00 mov dword ptr [ebp+var_3C+18h], 'txt'
$ = { C7 45 C4 25 6C 6F 63 50 8D 45 C4 C7 45 C8 61 6C 61 70 8B F9 C7 45 CC 70 64 61 74 50 B9 BD 88 17 75 C7 45 D0 61 25 5C 6C 8B DA C7 45 D4 6F 67 5F 67 C7 45 D8 6F 6C 64 2E C7 45 DC 74 78 74 00 }
// Import loaders
$ = { 51 50 57 56 B9 E6 8E 85 35 E8 ?? ?? ?? ?? FF D0 }
$ = { 6A 40 68 00 10 00 00 52 6A 00 FF 75 E0 B9 E3 18 90 72 E8 ?? ?? ?? ?? FF D0}
condition:
all of them
}
