rule macSpy
{
meta:
author = "AlienVault Labs"
type = "malware"
description = "MacSpy"
reference = "https://www.alienvault.com/blogs/labs-research/macspy-os-x-rat-as-a-service"
strings:
$header0 = {cf fa ed fe}
$header1 = {ce fa ed fe}
$header2 = {ca fe ba be}
$c1 = { 76 31 09 00 76 32 09 00 76 33 09 00 69 31 09 00 69 32 09 00 69 33 09 00 69 34 09 00 66 31 09 00 66 32 09 00 66 33 09 00 66 34 09 00 74 63 3A 00 }
condition:
($header0 at 0 or $header1 at 0 or $header2 at 0) and $c1
}
