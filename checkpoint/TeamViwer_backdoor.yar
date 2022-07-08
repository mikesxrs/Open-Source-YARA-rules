rule TeamViwer_backdoor
{

meta:
date = "2019-04-14"
description = "Detects malicious TeamViewer DLLs"
reference = "https://research.checkpoint.com/2019/finteam-trojanized-teamviewer-against-government-targets/"

strings:

// PostMessageW hook function
$x1 = {55 8b ec 8b 45 0c 3d 12 01 00 00 75 05 83 c8 ff eb 12 8b 55 14 52 8b 55 10 52 50 8b 45 08 50 e8}

condition:
uint16(0) == 0x5a4d and $x1
}
