rule NK_GOLDBACKDOOR_LNK_payload
{
meta:
author= "Silas Cutler (silas@Stairwell.com)"
description = "Detection for obfuscated Powershell contained in LNK file that deploys GOLDBACKDOOR"
reference = "https://stairwell.com/news/threat-research-the-ink-stained-trail-of-goldbackdoor/"
version = "0.1"
strings:
$ = "WriteByte($x0, $h-1, ($xmpw4[$h] -bxor $xmpw4[0]" ascii wide nocase
condition:
all of them
}
