rule osx_dok
{
meta:

author = "AlienVault Labs"

type = "malware"

description = "OSX/Dok"

reference = "https://www.alienvault.com/blogs/labs-research/diversity-in-recent-mac-malware"


strings:

$c1 = "/usr/local/bin/brew"

$c2 = "/usr/local/bin/tor"

$c3 = "/usr/local/bin/socat"

$c4 = "killall Safari"

& $c5 = "killall "Google Chrome""

$c6 = "killall firefox"

$c7 = "security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain %@"

condition:

all of them

}
