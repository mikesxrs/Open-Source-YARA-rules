rule osx_proton_b

{

meta:

author = "AlienVault Labs"

type = "malware"

description = "Mac.Backdoor.Systemd.1"

reference = "https://www.alienvault.com/blogs/labs-research/diversity-in-recent-mac-malware"

strings:

$c1 = "%@/%@%@%@%@%@"

$c2 = { 2e 00 68 00 61 00 73 00 } //. h a s

$c3 = "Network Configuration needs to update DHCP settings. Type your password to allow this."

$c4 = "root_password"

$c5 = "decryptData:withPassword:error:"

$c6 = "—–BEGIN PUBLIC KEY—–"

$c7 = "ssh_user"

condition:

5 of ($c*)

}
