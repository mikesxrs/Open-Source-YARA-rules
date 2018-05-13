rule bad_ComputraceAgent
{
  meta:
    description = "Absolute Computrace Agent Lacking Hardcoded Domain"
    thread_level = 3
    in_the_wild = true
	reference = "https://pastebin.com/nsv0tqUg"
	reference2 = "https://asert.arbornetworks.com/lojack-becomes-a-double-agent/"
	reference3 = "https://www.blackhat.com/docs/us-14/materials/us-14-Kamlyuk-Kamluk-Computrace-Backdoor-Revisited.pdf"
 
  strings:
    $a = { D1 E0 F5 8B 4D 0C 83 D1 00 8B EC FF 33 83 C3 04 }
    $b1 = { 72 70 63 6E 65 74 70 2E 65 78 65 00 72 70 63 6E 65 74 70 00 }
    $b2 = { 54 61 67 49 64 00 }
 
    $domain = { c6 d0 d4 c7 d6 dd 9b db d4 d8 d0 c4 c0 d0 c7 cc 9b d6 da d8 } // search.namequery.com XOR 0xb5
 
  condition:
    uint16(0) == 0x5a4d and
    filesize < 20KB and
    ($a or ($b1 and $b2))
    and not $domain
}
