rule IMPLANT_2_v1
{
meta:
      author = "US-CERT"
      description = "CORESHELL/SOURFACE"
      reference = "https://www.us-cert.gov/sites/default/files/publications/AR-17-20045_Enhanced_Analysis_of_GRIZZLY_STEPPE_Activity.pdf"

strings:
      $STR1 = { 8d ?? fa [2] e8 [2] FF FF C7 [2-5] 00 00 00 00 8D [2-5] 5? 6a 00 6a 01}

condition:
   	 (uint16(0) == 0x5A4D) and all of them
}

rule IMPLANT_2_v2
{
meta:
	author = "US-CERT"
	description = "CORESHELL/SOURFACE"
	reference = "https://www.us-cert.gov/sites/default/files/publications/AR-17-20045_Enhanced_Analysis_of_GRIZZLY_STEPPE_Activity.pdf"

strings:
	$STR1 = { 83 ?? 06 [7-17] fa [0-10] 45 [2-4] 48 [2-4] e8 [2] FF FF [6-8] 48 8d [3] 48 89 [3] 45 [2] 4? [1-2] 01}

condition:
	(uint16(0) == 0x5A4D) and all of them
}

rule IMPLANT_2_v3
{
meta:
	author = "US-CERT"
	description = "CORESHELL/SOURFACE"
	reference = "https://www.us-cert.gov/sites/default/files/publications/AR-17-20045_Enhanced_Analysis_of_GRIZZLY_STEPPE_Activity.pdf"

strings:
	$STR1 = {c1eb078d??01321c??33d2}
	$STR2 = {2b??83??060f83??000000eb0233}
	$STR3 = {89????89????8955??8945??3b??0f83??0000008d????8d????fe}

condition:
	(uint16(0) == 0x5A4D) and any of them
}

rule IMPLANT_2_v4
{
meta:
	author = "US-CERT"
	description = "CORESHELL/SOURFACE"
	reference = "https://www.us-cert.gov/sites/default/files/publications/AR-17-20045_Enhanced_Analysis_of_GRIZZLY_STEPPE_Activity.pdf"

strings:
	$STR1 = {55 8b ec 6a fe 68 [4] 68 [4] 64 A1 00 00 00 00 50 83 EC 0C 53 56 57 A1 [4] 31 45 F8 33 C5 50 8D 45 F0 64 A3 00 00 00 00 [8-14] 68 [4] 6a 01 [1-2] FF 15 [4] FF 15 [4] 3D B7 00 00 00 75 27}
condition:
 (uint16(0) == 0x5A4D) and all of them
}

rule IMPLANT_2_v5
{
meta:
      author = "US-CERT"
      description = "CORESHELL/SOURFACE"
      reference = "https://www.us-cert.gov/sites/default/files/publications/AR-17-20045_Enhanced_Analysis_of_GRIZZLY_STEPPE_Activity.pdf"

strings:
	$STR1 = {48 83 [2] 48 89 [3] c7 44 [6] 4c 8d 05 [3] 00 BA 01 00 00 00 33 C9 ff 15 [2] 00 00 ff 15 [2] 00 00 3D B7 00 00 00 75 ?? 48 8D 15 ?? 00 00 00 48 8B CC E8}

condition:
	(uint16(0) == 0x5A4D) and all of them
}

rule IMPLANT_2_v6
{
meta:
	author = "US-CERT"
	description = "CORESHELL/SOURFACE"
	reference = "https://www.us-cert.gov/sites/default/files/publications/AR-17-20045_Enhanced_Analysis_of_GRIZZLY_STEPPE_Activity.pdf"

strings:
	$STR1 = {e8 [2] ff ff 8b [0-6] 00 04 00 00 7F ?? [1-2] 00 02 00 00 7F ?? [1-2] 00 01 00 00 7F ??
    [1-2] 80 00 00 00 7F ?? 83 ?? 40 7F}
condition:
	(uint16(0) == 0x5A4D) and all of them
}

rule IMPLANT_2_v7
{
meta:
	author = "US-CERT"
	description = "CORESHELL/SOURFACE"
	reference = "https://www.us-cert.gov/sites/default/files/publications/AR-17-20045_Enhanced_Analysis_of_GRIZZLY_STEPPE_Activity.pdf"

strings:
	$STR1 = {0a 0f af d8 33 d2 8d 41 ff f7 75 ?? 8b 45 0c c1 eb 07 8d 79 01 32 1c 02 33 d2 8b c7 89 5d e4 bb 06 00 00 00 f7 f3 8b 45 0c 8d 59 fe 02 5d ff 32 1c 02 8b c1 33 d2 b9 06 00 00 00 f7 f1 8b 45 0c 8b cf 22 1c 02 8b 45 e4 8b 55 e0 08 d4 1f e8 3f 80 68 b4 5? ?7 2? ?8 b4 d? ?8 b?}
	$STR2 = {8d 9b 00 00 00 00 0f b6 5c 0a fe 8d 34 02 8b 45 ?? 03 c2 0f af d8 8d 7a 01 8d 42 ff 33 d2 f7 75 ?? c1 eb 07 8b c7 32 1c 0a 33 d2 b9 06 00 00 00 f7 f1 8a 4d ?? 8b 45 0c 80 e9 02 02 4d ?? 32 0c 02 8b 45 ?? 33 d2 f7 75 ?? 8b 45 0c 22 0c 02 8b d7 02 d9 30 1e 8b 4d 0c 8d 42 fe 3b 45 e8 8b 45 ?? 89 55 ?? 72 a0 5f 5e 5b 8b e5 5d c2 08 00}
condition:
	(uint16(0) == 0x5A4D) and any of them
}

rule IMPLANT_2_v8
{
meta:
	author = "US-CERT"
	description = "CORESHELL/SOURFACE"
	reference = "https://www.us-cert.gov/sites/default/files/publications/AR-17-20045_Enhanced_Analysis_of_GRIZZLY_STEPPE_Activity.pdf"

strings:
	$STR1 = {8b??448944246041f7e08bf2b8abaaaaaac1ee0289742458448b??41f7??8bcaba03000000c1e902890c248d044903c0442b??4489??24043bf10f83??0100008d1c764c896c24}
	$STR2 = {c541f7e0????????????8d0c5203c92bc18bc8??8d04??460fb60c??4002c7418d48ff4432c8b8abaaaaaaf7e1c1ea028d045203c02bc8b8abaaaaaa46220c??418d48fef7e1c1ea028d045203c02bc88bc1}
	$STR3 = {41f7e0c1ea02418bc08d0c5203c92bc18bc8428d041b460fb60c??4002c6418d48ff4432c8b8abaaaaaaf7e1c1ea028d045203c02bc8b8abaaaaaa}
	$STR4 = {46220c??418d48fef7e1c1ea028d04528b54245803c02bc88bc10fb64fff420fb604??410fafcbc1}

condition:
	(uint16(0) == 0x5A4D) and any of them
}

rule IMPLANT_2_v9
{
meta:
	author = "US-CERT"
	description = "CORESHELL/SOURFACE"
	reference = "https://www.us-cert.gov/sites/default/files/publications/AR-17-20045_Enhanced_Analysis_of_GRIZZLY_STEPPE_Activity.pdf"
strings:
	$STR1 = {8A C3 02 C0 02 D8 8B 45 F8 02 DB 83 C1 02 03 45 08 88 5D 0F 89 45 E8 8B FF 0F B6 5C 0E FE 8B 45 F8 03 C1 0F AF D8 8D 51 01 89 55 F4 33 D2 BF 06 00 00 00 8D 41 FF F7 F7 8B 45 F4 C1 EB 07 32 1C 32 33 D2 F7 F7 8A C1 02 45 0F 2C 02 32 04 32 33 D2 88 45 FF 8B C1 8B F7 F7 F6 8A 45 FF 8B 75 14 22 04 32 02 D8 8B 45 E8 30 1C 08 8B 4D F4 8D 51 FE 3B D7 72 A4 8B 45 E4 8B 7D E0 8B 5D F0 83 45 F8 06 43 89 5D F0 3B D8 0F 82 ?? ?? ?? ?? 3B DF 75 13 8D 04 7F 8B 7D 10 03 C0 2B F8 EB 09 33 C9 E9 5B FF FF FF 33 FF 3B 7D EC 0F 83 ?? ?? ?? ?? 8B 55 08 8A CB 02 C9 8D 04 19 02 C0 88 45 13 8D 04 5B 03 C0 8D 54 10 FE 89 45 E0 8D 4F 02 89 55 E4 EB 09 8D 9B 00 00 00 00 8B 45 E0 0F B6 5C 31 FE 8D 44 01 FE 0F AF D8 8D 51 01 89 55 0C 33 D2 BF 06 00 00 00 8D 41 FF F7 F7 8B 45 0C C1 EB 07 32 1C 32 33 D2 F7 F7 8A C1 02 45 13 2C 02 32 04 32 33 D2 88 45 0B 8B C1 8B F7 F7 F6 8A 45 0B 8B 75 14 22 04 32 02 D8 8B 45 E4 30 1C 01 8B 4D 0C }

condition:
	(uint16(0) == 0x5A4D or uint16(0) == 0xCFD0 or uint16(0) == 0xC3D4 or uint32(0) == 0x46445025 or uint32(1) == 0x6674725C) and all of them
}

rule IMPLANT_2_v10
{
meta:
	author = "US-CERT"
	description = "CORESHELL/SOURFACE"
	reference = "https://www.us-cert.gov/sites/default/files/publications/AR-17-20045_Enhanced_Analysis_of_GRIZZLY_STEPPE_Activity.pdf"

strings:
	$STR1 = { 83 ?? 06 [7-17] fa [0-10] 45 [2-4] 48 [2-4] e8 [2] FF FF [6-8] 48 8d [3] 48 89 [3] 45 [2] 4? [1-2] 01 }

condition:
	(uint16(0) == 0x5A4D) and all of them
}

rule IMPLANT_2_v11
{
meta:
	author = "US-CERT"
	description = "CORESHELL/SOURFACE"
	reference = "https://www.us-cert.gov/sites/default/files/publications/AR-17-20045_Enhanced_Analysis_of_GRIZZLY_STEPPE_Activity.pdf"

strings:
$STR1 = {55 8b ec 6a fe 68 [4] 68 [4] 64 A1 00 00 00 00 50 83 EC 0C 53 56 57 A1 [4] 31 45 F8 33 C5 50 8D 45 F0 64 A3 00 00 00 00 [8-14] 68 [4] 6a 01 [1-2] FF 15 [4] FF 15 [4] 3D B7 00 00 00 75 27}

condition:
	(uint16(0) == 0x5A4D) and all of them
}

rule IMPLANT_2_v12
{
meta:
	author = "US-CERT"
	description = "CORESHELL/SOURFACE"
	reference = "https://www.us-cert.gov/sites/default/files/publications/AR-17-20045_Enhanced_Analysis_of_GRIZZLY_STEPPE_Activity.pdf"

strings:
	$STR1 = {48 83 [2] 48 89 [3] c7 44 [6] 4c 8d 05 [3] 00 BA 01 00 00 00 33 C9 ff 15 [2] 00 00 ff 15 [2] 00 00 3D B7 00 00 00 75 ?? 48 8D 15 ?? 00 00 00 48 8B CC E8}

condition:
	(uint16(0) == 0x5A4D) and all of them
}

rule IMPLANT_2_v13
{
meta:
	author = "US-CERT"
	description = "CORESHELL/SOURFACE"
	reference = "https://www.us-cert.gov/sites/default/files/publications/AR-17-20045_Enhanced_Analysis_of_GRIZZLY_STEPPE_Activity.pdf"

strings:
	$STR1 = { 83 ?? 06 [7-17] fa [0-10] 45 [2-4] 48 [2-4] e8 [2] FF FF [6-8] 48 8d [3] 48 89 [3] 45 [2] 4? [1-2] 01}

condition:
	(uint16(0) == 0x5A4D) and all of them
}

rule IMPLANT_2_v14
{
meta:
	author = "US-CERT"
	description = "CORESHELL/SOURFACE"
	reference = "https://www.us-cert.gov/sites/default/files/publications/AR-17-20045_Enhanced_Analysis_of_GRIZZLY_STEPPE_Activity.pdf"

strings:
	$STR1 = {8b??448944246041f7e08bf2b8abaaaaaac1ee0289742458448b??41f7??8bcaba03000000c1e902890c248d044903c0442b??4489??24043bf10f83??0100008d1c764c896c24 }
	$STR2 = {c541f7e0????????????8d0c5203c92bc18bc8??8d04??460fb60c??4002c7418d48ff4432c8b8abaaaaaaf7e1c1ea028d045203c02bc8b8abaaaaaa46220c??418d48fef7e1c1ea028d045203c02bc88bc1}
	$STR3 = {41f7e0c1ea02418bc08d0c5203c92bc18bc8428d041b460fb60c??4002c6418d48ff4432c8b8abaaaaaaf7e1c1ea028d045203c02bc8b8abaaaaaa}
	$STR4 = {46220c??418d48fef7e1c1ea028d04528b54245803c02bc88bc10fb64fff420fb604??410fafcbc1}

condition:
	(uint16(0) == 0x5A4D) and any of them
}

rule IMPLANT_2_v15
{
meta:
	author = "US-CERT"
	description = "CORESHELL/SOURFACE"
	reference = "https://www.us-cert.gov/sites/default/files/publications/AR-17-20045_Enhanced_Analysis_of_GRIZZLY_STEPPE_Activity.pdf"

strings:
	$XOR_LOOP1 = { 32 1C 02 33 D2 8B C7 89 5D E4 BB 06 00 00 00 F7 F3 }
	$XOR_LOOP2 = { 32 1C 02 8B C1 33 D2 B9 06 00 00 00 F7 F1 }
	$XOR_LOOP3 = { 02 C3 30 06 8B 5D F0 8D 41 FE 83 F8 06 }
condition:
	(uint16(0) == 0x5A4D or uint16(0) == 0xCFD0 or uint16(0) == 0xC3D4 or uint32(0) == 0x46445025 or uint32(1) == 0x6674725C) and all of them
}

rule IMPLANT_2_v16
{
meta:
	author = "US-CERT"
	description = "CORESHELL/SOURFACE"
	reference = "https://www.us-cert.gov/sites/default/files/publications/AR-17-20045_Enhanced_Analysis_of_GRIZZLY_STEPPE_Activity.pdf"
strings:
	$OBF_FUNCT = { 0F B6 1C 0B 8D 34 08 8D 04 0A 0F AF D8 33 D2 8D 41 FF F7 75 F8 8B 45 0C C1 EB 07 8D 79 01 32 1C 02 33 D2 8B C7 89 5D E4 BB 06 00 00 00 F7 F3 8B 45 0C 8D 59 FE 02 5D FF 32 1C 02 8B C1 33 D2 B9 06 00 00 00 F7 F1 8B 45 0C 8B CF 22 1C 02 8B 45 E4 8B 55 E0 02 C3 30 06 8B 5D F0 8D 41 FE 83 F8 06 8B 45 DC 72 9A }

condition:
	(uint16(0) == 0x5A4D or uint16(0) == 0xCFD0 or uint16(0) == 0xC3D4 or uint32(0) == 0x46445025 or uint32(1) == 0x6674725C) and $OBF_FUNCT
}

rule IMPLANT_2_v17
{
meta:
	author = "US-CERT"
	description = "CORESHELL/SOURFACE"
	reference = "https://www.us-cert.gov/sites/default/files/publications/AR-17-20045_Enhanced_Analysis_of_GRIZZLY_STEPPE_Activity.pdf"

strings:
	$STR1 = { 24108b44241c894424148b4424246836 }
	$STR2 = { 518d4ddc516a018bd08b4de4e8360400 }
	$STR3 = { e48178061591df75740433f6eb1a8b48 }
	$STR4 = { 33d2f775f88b45d402d903c641321c3a }
	$STR5 = { 006a0056ffd083f8ff74646a008d45f8 }

condition:
	(uint16(0) == 0x5A4D) and 2 of them
}

rule IMPLANT_2_v18
{
meta:
	author = "US-CERT"
	description = "CORESHELL/SOURFACE"
	reference = "https://www.us-cert.gov/sites/default/files/publications/AR-17-20045_Enhanced_Analysis_of_GRIZZLY_STEPPE_Activity.pdf"
strings:
	$STR1 = { 8A C1 02 C0 8D 1C 08 8B 45 F8 02 DB 8D 4A 02 8B 55 0C 88 5D FF 8B 5D EC 83 C2
FE 03 D8 89 55 E0 89 5D DC 8D 49 00 03 C1 8D 34 0B 0F B6 1C 0A 0F AF D8 33 D2 8D 41 FF F7 75
F4 8B 45 0C C1 EB 07 8D 79 01 32 1C 02 33 D2 8B C7 89 5D E4 BB 06 00 00 00 F7 F3 8B 45 0C 8D
59 FE 02 5D FF 32 1C 02 8B C1 33 D2 B9 06 00 00 00 F7 F1 8B 45 0C 8B CF 22 1C 02 8B 45 E4 8B
55 E0 02 C3 30 06 8B 5D DC 8D 41 FE 83 F8 06 8B 45 F8 72 9B 8B 4D F0 8B 5D D8 8B 7D 08 8B F0
41 83 C6 06 89 4D F0 89 75 F8 3B 4D D4 0F 82 ?? ?? ?? ?? 8B 55 E8 3B CB 75 09 8D 04 5B 03 C0 2B
F8 EB 02 33 FF 3B FA 0F 83 ?? ?? ?? ?? 8B 5D EC 8A C1 02 C0 83 C3 FE 8D 14 08 8D 04 49 02 D2 03
C0 88 55 0B 8D 48 FE 8D 57 02 03 C3 89 4D D4 8B 4D 0C 89 55 F8 89 45 D8 EB 06 8D 9B 00 00 00
00 0F B6 5C 0A FE 8D 34 02 8B 45 D4 03 C2 0F AF D8 8D 7A 01 8D 42 FF 33 D2 F7 75 F4 C1 EB 07
8B C7 32 1C 0A 33 D2 B9 06 00 00 00 F7 F1 8A 4D F8 8B 45 0C 80 E9 02 02 4D 0B 32 0C 02 8B 45
F8 33 D2 F7 75 F4 8B 45 0C 22 0C 02 8B D7 02 D9 30 1E 8B 4D 0C 8D 42 FE 3B 45 E8 }

condition:
	(uint16(0) == 0x5A4D or uint16(0) == 0xCFD0 or uint16(0) == 0xC3D4 or uint32(0) == 0x46445025 or uint32(1) == 0x6674725C) and all of them
}

rule IMPLANT_2_v19
{
meta:
	author = "US-CERT"
	description = "CORESHELL/SOURFACE"
	reference = "https://www.us-cert.gov/sites/default/files/publications/AR-17-20045_Enhanced_Analysis_of_GRIZZLY_STEPPE_Activity.pdf"
strings:
	$obfuscated_RSA1 = { 7C 41 B4 DB ED B0 B8 47 F1 9C A1 49 B6 57 A6 CC D6 74 B5 52 12 4D
FC B1 B6 3B 85 73 DF AB 74 C9 25 D8 3C EA AE 8F 5E D2 E3 7B 1E B8 09 3C AF 76 A1 38 56 76
BB A0 63 B6 9E 5D 86 E4 EC B0 DC 89 1E FA 4A E5 79 81 3F DB 56 63 1B 08 0C BF DC FC 75 19
3E 1F B3 EE 9D 4C 17 8B 16 9D 99 C3 0C 89 06 BB F1 72 46 7E F4 0B F6 CB B9 C2 11 BE 5E 27 94
5D 6D C0 9A 28 F2 2F FB EE 8D 82 C7 0F 58 51 03 BF 6A 8D CD 99 F8 04 D6 F7 F7 88 0E 51 88 B4
E1 A9 A4 3B }
	$cleartext_RSA1 = { 06 02 00 00 00 A4 00 00 52 53 41 31 00 04 00 00 01 00 01 00 AF BD 26 C9
04 65 45 9F 0E 3F C4 A8 9A 18 C8 92 00 B2 CC 6E 0F 2F B2 71 90 FC 70 2E 0A F0 CA AA 5D F4 CA
7A 75 8D 5F 9C 4B 67 32 45 CE 6E 2F 16 3C F1 8C 42 35 9C 53 64 A7 4A BD FA 32 99 90 E6 AC EC
C7 30 B2 9E 0B 90 F8 B2 94 90 1D 52 B5 2F F9 8B E2 E6 C5 9A 0A 1B 05 42 68 6A 3E 88 7F 38 97
49 5F F6 EB ED 9D EF 63 FA 56 56 0C 7E ED 14 81 3A 1D B9 A8 02 BD 3A E6 E0 FA 4D A9 07 5B
E6 }

condition:
	(uint16(0) == 0x5A4D or uint16(0) == 0xCFD0 or uint16(0) == 0xC3D4 or uint32(0) == 0x46445025 or uint32(1) == 0x6674725C) and any of them
}

rule IMPLANT_2_v20
{
meta:
	author = "US-CERT"
	description = "CORESHELL/SOURFACE"
	reference = "https://www.us-cert.gov/sites/default/files/publications/AR-17-20045_Enhanced_Analysis_of_GRIZZLY_STEPPE_Activity.pdf"

strings:
	$func = { 0F B6 5C 0A FE 8D 34 02 8B 45 D4 03 C2 0F AF D8 8D 7A 01 8D 42 FF 33 D2 F7 75
F4 C1 EB 07 8B C7 32 1C 0A 33 D2 B9 06 00 00 00 F7 F1 8A 4D F8 8B 45 0C 80 E9 02 02 4D 0B 32
0C 02 8B 45 F8 33 D2 F7 75 F4 8B 45 0C 22 0C 02 8B D7 02 D9 30 1E 8B 4D 0C 8D 42 FE 3B 45 E8
8B 45 D8 89 55 F8 72 A0 }

condition:
	(uint16(0) == 0x5A4D or uint16(0) == 0xCFD0 or uint16(0) == 0xC3D4 or uint32(0) == 0x46445025 or uint32(1) == 0x6674725C) and all of them
}
