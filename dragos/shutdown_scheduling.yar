rule shutdown_scheduling{
meta:
description = "Shutdown scheduling"
author = "Dragos Inc"
reference = "https://troopers.de/downloads/troopers18/TR18_DM_Mind-The-Gap.pdf"
strings:
$s1 = { 68 44 43 01 10 8d 85 d8 f9 ff ff 50 ff 15 1c d2 00 10 85 c0 74 }
$s2 = { f6 05 44 f1 01 10 04 b8 6c 43 01 10 75 05 }
$s3 = { 56 57 8d 8d ?? ?? ?? ff 51 50 8d 85 ?? ?? ?? ff 68 a8 42 01 10 }
condition:
all of ($s*)
}
