rule NK_GOLDBACKDOOR_obf_payload
{
meta:
author= "Silas Cutler (silas@Stairwell.com)"
description = "Detection for encoded shellcode payload downloaded by LNK file that drops GOLDBACKDOOR"
reference = "https://stairwell.com/news/threat-research-the-ink-stained-trail-of-goldbackdoor/"
version = "0.1"
strings:
$init = { e6b3 6d0a 6502 1e67 0aee e7e6 e66b eac2 }
condition:
$init at 0
}
