rule embedded_psexec{
meta:
description = "Look for indications of embedded psexec"
author = "Dragos Inc"
reference = "https://troopers.de/downloads/troopers18/TR18_DM_Mind-The-Gap.pdf"
strings:
$mz = "!This program cannot be run in DOS mode." ascii wide
$s1 = "-accepteula -s" ascii wide
$s2 = ",Sysinternals" ascii wide
condition:
all of ($s*) and #mz > 1
}
