rule mac_bd_systemd
{

meta:

author = "AlienVault Labs"

type = "malware"

description = "OSX/Proton.B"

reference = "https://www.alienvault.com/blogs/labs-research/diversity-in-recent-mac-malware"

strings:

$c1 = "This file is corrupted and connot be opened"

$c2 = "whatismyip.akamai.com"

$c3 = ";chflags hidden"

$c4 = "%keymod%"

$c5 = "* *-<4=w"

condition:

3 of ($c*)

}
