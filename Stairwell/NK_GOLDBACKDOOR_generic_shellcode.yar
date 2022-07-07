rule NK_GOLDBACKDOOR_generic_shellcode
{
meta:
author= "Silas Cutler (silas@Stairwell.com)"
description = "Generic detection for shellcode used to drop GOLDBACKDOOR"
reference = "https://stairwell.com/news/threat-research-the-ink-stained-trail-of-goldbackdoor/"
version = "0.1"
strings:
$ = { B9 8E 8A DD 8D 8B F0 E8 ?? ?? ?? ?? FF D0 }
$ = { B9 8E AB 6F 40 [1-10] 50 [1-10] E8 ?? ?? ?? ?? FF D0 }
condition:
all of them
}
