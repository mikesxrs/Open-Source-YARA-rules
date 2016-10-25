rule Dropper_Hancitor {
  meta:
    authors = "Nick Hoffman & Jeremy Humble - Morphick Inc."
    last_update = "2016-08-19"
    description = "rule to find unpacked Hancitor, useful against memory dumps"
    hash = "587a530cc82ff01d6b2d387d9b558299b0eb36e7e2c274cd887caa39fcc47c6f"
    ref = "http://www.morphick.com/resources/lab-blog/closer-look-hancitor"

  strings:
    /*
    .text:00401C02 83 FA 3A                                      cmp     edx, ':'
    .text:00401C05 75 6B                                         jnz     short loc_401C72
    .text:00401C07 B8 01 00 00 00                                mov     eax, 1
    .text:00401C0C 6B C8 00                                      imul    ecx, eax, 0
    .text:00401C0F 8B 55 08                                      mov     edx, [ebp+arg_0]
    .text:00401C12 0F BE 04 0A                                   movsx   eax, byte ptr [edx+ecx]
    .text:00401C16 83 F8 72                                      cmp     eax, 'r'
    .text:00401C19 74 50                                         jz      short loc_401C6B
    .text:00401C1B B9 01 00 00 00                                mov     ecx, 1
    .text:00401C20 6B D1 00                                      imul    edx, ecx, 0
    .text:00401C23 8B 45 08                                      mov     eax, [ebp+arg_0]
    .text:00401C26 0F BE 0C 10                                   movsx   ecx, byte ptr [eax+edx]
    .text:00401C2A 83 F9 75                                      cmp     ecx, 'u'
    .text:00401C2D 74 3C                                         jz      short loc_401C6B
    .text:00401C2F BA 01 00 00 00                                mov     edx, 1
    .text:00401C34 6B C2 00                                      imul    eax, edx, 0
    .text:00401C37 8B 4D 08                                      mov     ecx, [ebp+arg_0]
    .text:00401C3A 0F BE 14 01                                   movsx   edx, byte ptr [ecx+eax]
    .text:00401C3E 83 FA 64                                      cmp     edx, 'd'
    .text:00401C41 74 28                                         jz      short loc_401C6B
    .text:00401C43 B8 01 00 00 00                                mov     eax, 1
    .text:00401C48 6B C8 00                                      imul    ecx, eax, 0
    .text:00401C4B 8B 55 08                                      mov     edx, [ebp+arg_0]
    .text:00401C4E 0F BE 04 0A                                   movsx   eax, byte ptr [edx+ecx]
    .text:00401C52 83 F8 6C                                      cmp     eax, 'l'
    .text:00401C55 74 14                                         jz      short loc_401C6B
    .text:00401C57 B9 01 00 00 00                                mov     ecx, 1
    .text:00401C5C 6B D1 00                                      imul    edx, ecx, 0
    .text:00401C5F 8B 45 08                                      mov     eax, [ebp+arg_0]
    .text:00401C62 0F BE 0C 10                                   movsx   ecx, byte ptr [eax+edx]
    .text:00401C66 83 F9 6E                                      cmp     ecx, 'n'
    */

    $arg_parsing = { 83 f? ( 3a | 6c | 64 | 75 | 74 ) 7? ?? b? 01 00 00 00 6b ?? 00 8b ?? 08 0f be 0? ?? }

    /*   

    .text:00401116 B8 01 00 00 00                                mov     eax, 1
    .text:0040111B 85 C0                                         test    eax, eax
    .text:0040111D 74 49                                         jz      short loc_401168
    .text:0040111F 8B 0D 88 5B 40 00                             mov     ecx, dword_405B88
    .text:00401125 0F BE 11                                      movsx   edx, byte ptr [ecx]
    .text:00401128 83 FA 7C                                      cmp     edx, '|'
    .text:0040112B 74 0C                                         jz      short loc_401139
    .text:0040112D A1 88 5B 40 00                                mov     eax, dword_405B88
    .text:00401132 0F BE 08                                      movsx   ecx, byte ptr [eax]
    .text:00401135 85 C9                                         test    ecx, ecx
    .text:00401137 75 08                                         jnz     short loc_401141

    */

    $pipe_delimit = { b8 01 00 00 00 85 c0 7? ?? 8b 0d ?? ?? ?? ?? 0f be 11 83 fa 7c 7? }

    $fmt_string = "GUID=%I64u&BUILD=%s&INFO=%s&IP=%s&TYPE=1&WIN=%d.%d(%s)"

    /*

    .text:00401AEE 83 FA 3C                                      cmp     edx, '<'
    .text:00401AF1 75 48                                         jnz     short loc_401B3B
    .text:00401AF3 B8 01 00 00 00                                mov     eax, 1
    .text:00401AF8 C1 E0 00                                      shl     eax, 0
    .text:00401AFB 0F BE 8C 05 FC FD FF FF                       movsx   ecx, [ebp+eax+Buffer]
    .text:00401B03 83 F9 21                                      cmp     ecx, '!'
    .text:00401B06 75 33                                         jnz     short loc_401B3B
    .text:00401B08 BA 01 00 00 00                                mov     edx, 1
    .text:00401B0D D1 E2                                         shl     edx, 1
    .text:00401B0F 0F BE 84 15 FC FD FF FF                       movsx   eax, [ebp+edx+Buffer]
    .text:00401B17 83 F8 64                                      cmp     eax, 'd'
    .text:00401B1A 75 1F                                         jnz     short loc_401B3B
    .text:00401B1C B9 01 00 00 00                                mov     ecx, 1
    .text:00401B21 6B D1 03                                      imul    edx, ecx, 3
    .text:00401B24 0F BE 84 15 FC FD FF FF                       movsx   eax, [ebp+edx+Buffer]
    .text:00401B2C 83 F8 6F                                      cmp     eax, 'o'

    */

    $connectivty_google_check = { 83 fa 3c 7? ?? b8 01 00 00 00 c1 e0 00 0f be 8c 05 fc fd ff ff 83 f9 21 7? ?? ba 01 00 00 00 d1 e2 0f be 84 15 fc fd ff ff 83 f8 64 7? ?? b9 01 00 00 00 6b d1 03 0f be 84 15 fc fd ff ff 83 f8 6f }

  condition:

    #arg_parsing > 1 or any of ($pipe_delimit, $fmt_string,$connectivty_google_check)

}