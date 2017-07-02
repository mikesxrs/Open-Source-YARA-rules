rule HeartBleedWin32
{
 meta:
  author = "NCCGROUP"
  reference = "https://www.nccgroup.trust/uk/about-us/newsroom-and-events/blogs/2014/june/writing-robust-yara-detection-rules-for-heartbleed/"
  description = "rule to detect heartbleed"
 strings:
  $opensslmini = {E8 ?? ?? ?? ?? 8B 4C 24 24 8B E8 8D 7D 01 8B C3 C6 45 00 02 C1 E8 08 53 88 07 88 5F 01 51 83 C7 02 57 E8 ?? ?? ?? ??}
  $heartbleedpatch = {83 F9 13 73 ?? 5F 33 C0 5E 59 C3 0F ?? ?? ?? 0F ?? ??}
 condition:
  $opensslmini and not $heartbleedpatch
}
