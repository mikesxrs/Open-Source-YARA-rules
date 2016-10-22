rule banswift :banswift {
meta:
description = “Yara rule to detect samples that share wiping function with banswift”
reference = "https://www.blueliv.com/research/recap-of-cyber-attacks-targeting-swift/"
threat_level = 10

strings:
$snippet1 = {88 44 24 0D B9 FF 03 00 00 33 C0 8D 7C 24 2D C6 44 24 2C 5F 33 DB F3 AB 66 AB 53 68 80 00 00 00 6A 03 53 AA 8B 84 24 40 10 00 00 53 68 00 00 00 40 50 C6 44 24 2A FF 88 5C 24 2B C6 44 24 2C 7E C6 44 24 2D E7}
$snippet2 = {25 FF 00 00 00 B9 00 04 00 00 8A D0 8D 7C 24 30 8A F2 8B C2 C1 E0 10 66 8B C2 F3 AB}
condition:
all of ($snippet*)
}
