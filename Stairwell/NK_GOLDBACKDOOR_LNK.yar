rule NK_GOLDBACKDOOR_LNK
{
meta:
author= "Silas Cutler (silas@Stairwell.com)"
description = "Detection for LNK file used to deploy GOLDBACKDOOR"
reference = "https://stairwell.com/news/threat-research-the-ink-stained-trail-of-goldbackdoor/"
version = "0.1"
strings:
$ = "WINWORD.exe" wide nocase
$ = "$won11 =\"$temple=" wide
$ = "dirPath -Match 'System32' -or $dirPath -Match 'Program Files'" wide
condition:
2 of them and uint16(0) == 0x4c
}
