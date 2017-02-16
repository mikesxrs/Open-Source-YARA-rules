rule APT28_IMPLANT_1_v1
{
meta:
      author = "US-CERT"
      description = "X-AGENT/CHOPSTICK"
      reference = "https://www.us-cert.gov/sites/default/files/publications/AR-17-20045_Enhanced_Analysis_of_GRIZZLY_STEPPE_Activity.pdf"
strings:
      $STR1 = {6A ?? E8 ?? ?? FF FF 59 85 C0 74 0B 8B C8 E8 ?? ?? FF FF 8B F0 EB 02 33 F6 8B CE E8 ?? ?? FF FF 85 F6 74 0E 8B CE E8 ?? ?? FF FF 56 E8 ?? ?? FF FF 59}
condition:
      (uint16(0) == 0x5A4D) and all of them
}

rule APT28_IMPLANT_1_v2
{
meta:
      author = "US-CERT"
      description = "X-AGENT/CHOPSTICK"
      reference = "https://www.us-cert.gov/sites/default/files/publications/AR-17-20045_Enhanced_Analysis_of_GRIZZLY_STEPPE_Activity.pdf"

strings:
      $STR1 = {83 3E 00 53 74 4F 8B 46 04 85 C0 74 48 83 C0 02 50 E8 ?? ?? 00 00 8B D8 59 85 DB 74 38 8B 4E 04 83 F9 FF 7E 21 57 }
      $STR2 = {55 8B EC 8B 45 08 3B 41 08 72 04 32 C0 EB 1B 8B 49 04 8B 04 81 80 78 19 01 75 0D FF 70 10 FF [5] 85 C0 74 E3 }

condition:
      (uint16(0) == 0x5A4D) and any of them
}

rule APT28_IMPLANT_1_v3
{
meta:
      author = "US-CERT"
      description = "X-AGENT/CHOPSTICK"
      reference = "https://www.us-cert.gov/sites/default/files/publications/AR-17-20045_Enhanced_Analysis_of_GRIZZLY_STEPPE_Activity.pdf"

strings:
      $rol7encode = { 0F B7 C9 C1 C0 07 83 C2 02 33 C1 0F B7 0A 47 66 85 C9 75 }
condition:
      (uint16(0) == 0x5A4D or uint16(0) == 0xCFD0 or uint16(0) == 0xC3D4 or uint32(0) == 0x46445025 or uint32(1) == 0x6674725C) and all of them
}

rule APT28_IMPLANT_1_v4
{
meta:
      author = "US-CERT"
      description = "X-AGENT/CHOPSTICK"
      reference = "https://www.us-cert.gov/sites/default/files/publications/AR-17-20045_Enhanced_Analysis_of_GRIZZLY_STEPPE_Activity.pdf"
 strings:
      $XOR_LOOP = { 8B 45 FC 8D 0C 06 33 D2 6A 0B 8B C6 5B F7 F3 8A 82 ?? ?? ?? ?? 32 04 0F 46 88 01 3B 75 0C 7C E0 }
 condition:
      (uint16(0) == 0x5A4D) and all of them
}

rule APT28_IMPLANT_1_v5
{
meta:
      author = "US-CERT"
      description = "X-AGENT/CHOPSTICK"
      reference = "https://www.us-cert.gov/sites/default/files/publications/AR-17-20045_Enhanced_Analysis_of_GRIZZLY_STEPPE_Activity.pdf"
strings:
      $drivername = { 6A 30 ?? 6A 33 [5] 6A 37 [5] 6A 32 [5] 6A 31 [5] 6A 77 [5] 6A 69 [5] 6A 6E [5] 6A 2E [5] 6A 73 [5-9] 6A 79 [5] 6A 73 }
      $mutexname = { C7 45 ?? 2F 2F 64 66 C7 45 ?? 63 30 31 65 C7 45 ?? 6C 6C 36 7A C7 45 ?? 73 71 33 2D C7 45 ?? 75 66 68 68 66 C7 45 ?? 66 }
condition:
      (uint16(0) == 0x5A4D or uint16(0) == 0xCFD0 or uint16(0) == 0xC3D4 or uint32(0) == 0x46445025 or uint32(1) == 0x6674725C) and any of them
}

rule APT28_IMPLANT_1_v6
{
meta:
      author = "US-CERT"
      description = "X-AGENT/CHOPSTICK"
      reference = "https://www.us-cert.gov/sites/default/files/publications/AR-17-20045_Enhanced_Analysis_of_GRIZZLY_STEPPE_Activity.pdf"

strings:
      $XORopcodes_eax = { 35 (22 07 15 0e|56 d7 a7 0a) }
      $XORopcodes_others = { 81 (f1|f2|f3|f4|f5|f6|f7) (22 07 15 0e|56 d7 a7 0a) }

condition:
      (uint16(0) == 0x5A4D or uint16(0) == 0xCFD0 or uint16(0) == 0xC3D4 or uint32(0) == 0x46445025) and any of them
}

rule APT28_IMPLANT_1_v7
{
meta:
      author = "US-CERT"
      description = "X-AGENT/CHOPSTICK"
      reference = "https://www.us-cert.gov/sites/default/files/publications/AR-17-20045_Enhanced_Analysis_of_GRIZZLY_STEPPE_Activity.pdf"

strings:
      $XOR_FUNCT = { C7 45 ?? ?? ?? 00 10 8B 0E 6A ?? FF 75 ?? E8 ?? ?? FF FF }

condition:
      (uint16(0) == 0x5A4D) and all of them
}
